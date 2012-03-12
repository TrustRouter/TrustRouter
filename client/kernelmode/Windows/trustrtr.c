#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>

#include "trustrtr.h"

// {80E84D14-A7DD-4b5f-B5BD-51BCD21EAA49}
DEFINE_GUID(TRUSTRTR_CALLOUT_DRIVER_GUID, 
0x80e84d14, 0xa7dd, 0x4b5f, 0xb5, 0xbd, 0x51, 0xbc, 0xd2, 0x1e, 0xaa, 0x49);

PDEVICE_OBJECT pDeviceObject;
LIST_ENTRY gReinjectListHead = {0}; 
UNICODE_STRING gSymLinkName = {0};
FAST_MUTEX gListMutex;

NTSTATUS DriverEntry(
   IN  PDRIVER_OBJECT  pDriverObject,
   IN  PUNICODE_STRING registryPath)
{
	NTSTATUS status;
	UNICODE_STRING usDriverName, usDosDeviceName;
	
	RtlInitUnicodeString(&usDriverName, L"\\Device\\trustrtr");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\trustrtr");
	
	gSymLinkName = usDosDeviceName;	
	IoCreateSymbolicLink(&gSymLinkName, &usDriverName);
	
	//DbgPrint("----------------------------------------------------------------\n");
	
	status = IoCreateDevice(
		pDriverObject,
		0,
		&usDriverName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDeviceObject);
	
	pDriverObject->DriverUnload = DriverUnload;	
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = TrustrtrCalloutCreate;
	pDriverObject->MajorFunction[IRP_MJ_READ] = TrustrtrCalloutRead;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = TrustrtrCalloutClose;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = TrustrtrCalloutWrite;
	
	pDeviceObject->Flags = DO_BUFFERED_IO;		

	ExInitializeFastMutex(&gListMutex);	
	InitializeListHead(&gReinjectListHead);	
	RegisterCallout();
	
	return status;
}

VOID RegisterCallout() 
{
	NTSTATUS status;
	
	FWPS_CALLOUT1 sCallout;
	UINT32 calloutId;
	
	RtlZeroMemory(&sCallout, sizeof(FWPS_CALLOUT1));
	
	sCallout.calloutKey = TRUSTRTR_CALLOUT_DRIVER_GUID;
	sCallout.flags = 0;
	sCallout.classifyFn = TrustrtrClassify;
	sCallout.notifyFn = TrustrtrNotify;
	sCallout.flowDeleteFn = NULL;
	
	status = FwpsCalloutRegister1(
		pDeviceObject,
		&sCallout,
		&calloutId);
	
	if (status == STATUS_SUCCESS) {
		//DbgPrint("-+-+-+- trustrtr: register was successful.\n");
	} else if (status == STATUS_FWP_ALREADY_EXISTS) {
		DbgPrint("TrustRouter Error: Callout could not be registered.\n");
	} else {
		DbgPrint("TrustRouter Error: Callout could not be registered. Status: %0x\n", status);
	}
}

VOID NTAPI TrustrtrClassify(
    IN const FWPS_INCOMING_VALUES0  *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0  *inMetaValues,
    IN OUT VOID  *layerData,
	IN const VOID *classifyContext,
    IN const FWPS_FILTER1  *filter,
    IN UINT64  flowContext,
    OUT FWPS_CLASSIFY_OUT0  *classifyOut) 
{
	NET_BUFFER_LIST *netBufferList = (NET_BUFFER_LIST *)layerData;
	NET_BUFFER *netBuffer;
	NTSTATUS status;
	FWPS_PACKET_INJECTION_STATE injectionState;
	HANDLE injectionHandle = NULL;
	NET_BUFFER_LIST *clonedNetBufferList = NULL;
	ICMP_V6_REINJECT_INFO *reinjectInfo;

	//DbgPrint("================== ClassifyFn ============================\n");
	//DbgPrint("Packet from Filter with ID %d\n", filter->filterId);

	// Get a handle for injection. Assumption: We only want to inject IPv6 packets.
	status = FwpsInjectionHandleCreate0(
						AF_INET6,
						FWPS_INJECTION_TYPE_TRANSPORT,
						&injectionHandle);
	
	if (status == STATUS_FWP_TCPIP_NOT_READY) {
		DbgPrint("TrustRouter Error: TCPIP stack not ready for injection.\n");
	} else if (status == STATUS_SUCCESS) {
		//DbgPrint("Injection handle created successfully.\n");
	} else {
		DbgPrint("TrustRouter Error:  Error when trying to get injection handle: %0x\n", status);
	}					
	
	// Check if the packet was previously injected by this driver.
	// In this case, we can assume that it is to be permitted.
	injectionState = FwpsQueryPacketInjectionState0(
						injectionHandle,
						netBufferList,
						NULL);                     
						
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF 
		|| injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF
		|| injectionState == FWPS_PACKET_INJECTED_BY_OTHER) {
			classifyOut->actionType = FWP_ACTION_PERMIT;
			//DbgPrint("This packet has been injected before. Permitting it.\n");
			return;
	}
    
    netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    
    /*
        To be able to insert the packet into the TCP/IP stack later,
        we need to go back to the start of the IP-header (we are at the beginning of the transport payload).
        NOTE: This adjustment has to be undone before returning from
        TrustrtrClassify using NdisAdvanceNetBufferDataStart !
    */	    
    NdisRetreatNetBufferDataStart(netBuffer,
                                  inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize,
                                  0,
                                  NULL);
    
    FwpsAllocateCloneNetBufferList0(
        netBufferList,
        NULL,
        NULL,
        0,
        &clonedNetBufferList);
        
    //DbgPrint("Cloned Net Buffer List after Retreating to IP Header:\n");
    //printDataFromNetBufferList(clonedNetBufferList);
    
    NdisAdvanceNetBufferDataStart(netBuffer,
                                  inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize,
                                  0,
                                  NULL);                             
    
    // We want to inspect the packet further in user mode, so absorb and block
    // the packet for the moment. If we want allow it, we have to reinject it later.
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->flags = FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    
    // Allocate and populate a ICMP_V6_REINJECT_INFO structure that holds all information
    // necessary to reinject the packet later if necessary.
    // If the decision is made in user mode to permit the packet, this information
    // will be read in completeOperationAndReinjectPacket().
    
    reinjectInfo = ExAllocatePoolWithTag(PagedPool, sizeof(ICMP_V6_REINJECT_INFO), "denS");
    
    reinjectInfo->netBufferList = clonedNetBufferList;
    reinjectInfo->injectionHandle = injectionHandle;
    reinjectInfo->af = AF_INET6;
    reinjectInfo->interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_INTERFACE_INDEX].value.uint32;
    //DbgPrint("InterfaceIndex is %d\n", reinjectInfo->interfaceIndex);
    reinjectInfo->subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_SUB_INTERFACE_INDEX].value.uint32;
    reinjectInfo->hasBeenRead = FALSE;
        
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
        reinjectInfo->compartmentId = inMetaValues->compartmentId;
    } else {
        reinjectInfo->compartmentId = UNSPECIFIED_COMPARTMENT_ID;
    }
    
    ExAcquireFastMutex(&gListMutex);	
    InsertTailList(&gReinjectListHead, &(reinjectInfo->listEntry));	
    ExReleaseFastMutex(&gListMutex);
    
    return;
}

NTSTATUS TrustrtrCalloutCreate(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	return STATUS_SUCCESS;
}

NTSTATUS TrustrtrCalloutClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	return STATUS_SUCCESS;
}

NTSTATUS TrustrtrCalloutRead(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_BUFFER_TOO_SMALL;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
	PCHAR pReadDataBuffer;
	PCHAR pReturnData;
	UINT dwDataRead = 0;
	UINT totalReadBytes;
	
	if (!IsListEmpty(&gReinjectListHead)) {
		NET_BUFFER *pNetBuffer;
		PVOID packetBuf, Ppacket = NULL;
		ICMP_V6_REINJECT_INFO *pReinjectInfoToRead = NULL;
		
		// Look in the gReinjectList for reinject infos that have not yet been read.
		// If one is found, write it to the read buffer.
		PLIST_ENTRY pListEntry = gReinjectListHead.Flink;
		while (pListEntry != &gReinjectListHead) {
			ICMP_V6_REINJECT_INFO *pReinjectInfo = CONTAINING_RECORD(pListEntry, ICMP_V6_REINJECT_INFO, listEntry);
			if (!pReinjectInfo->hasBeenRead) {
				pReinjectInfoToRead = pReinjectInfo;
				break;
			}					
			pListEntry = pListEntry->Flink;
		}
		
		if (pReinjectInfoToRead != NULL) {			
			UINT packetByteCount;
			IF_INDEX interfaceIndex = pReinjectInfoToRead->interfaceIndex;

			pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pReinjectInfoToRead->netBufferList);

			packetBuf = ExAllocatePoolWithTag(PagedPool, NET_BUFFER_DATA_LENGTH(pNetBuffer), "denS");
			packetByteCount = NET_BUFFER_DATA_LENGTH(pNetBuffer);
			
            // NdisGetDataBuffer may either return a pointer to the packet data
            // OR it can assign the packet data to the 3rd parameter.
			Ppacket = NdisGetDataBuffer(pNetBuffer,
							  NET_BUFFER_DATA_LENGTH(pNetBuffer),
							  packetBuf,
							  1,
							  0);
							  
			if (Ppacket == NULL) {
				pReturnData = packetBuf;
			} else {
				pReturnData = Ppacket;
			}	
			
			pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
			
			if(pIoStackIrp) {
				pReadDataBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
				totalReadBytes = packetByteCount + sizeof(&interfaceIndex) + sizeof(pReinjectInfoToRead);
				
				if(pReadDataBuffer && pIoStackIrp->Parameters.Read.Length >= totalReadBytes)
				{
					// First, write the address of the reinject structure into the buffer.
					// It is used to identify the packet when writing back to this driver.
					RtlCopyMemory(pReadDataBuffer, &pReinjectInfoToRead, sizeof(&pReinjectInfoToRead));
					//DbgPrint("READ: Copied Address %p to buffer.\n", pReinjectInfoToRead);
					// Now write the interface identifier, a 32-bit unsigned integer, to the buffer.
					// It is needed as the scope id in userland.
					RtlCopyMemory(pReadDataBuffer + sizeof(&pReinjectInfoToRead), &interfaceIndex, sizeof(&interfaceIndex));
					//DbgPrint("READ: Copied Interface Identifier %d to buffer.\n", interfaceIndex);
					// Now, write the byte content of the packet into the buffer.
					RtlCopyMemory(pReadDataBuffer + sizeof(&pReinjectInfoToRead) + sizeof(&interfaceIndex), pReturnData, packetByteCount);
					//DbgPrint("READ: Copied Packet Data to buffer.\n");
					dwDataRead = packetByteCount + sizeof(&pReinjectInfoToRead) + sizeof(&interfaceIndex);
					
					pReinjectInfoToRead->hasBeenRead = TRUE;
					
					status = STATUS_SUCCESS;
				}
			}
		}		
	}
	
	Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = dwDataRead;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return status;
}
NTSTATUS TrustrtrCalloutWrite(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
    PCHAR pWriteDataBuffer;
	USER_MODE_CLASSIFICATION_RESULT *pClassificationResult;
	PLIST_ENTRY pListEntry;
	BOOLEAN foundEntry = FALSE;
	
	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	
	if (pIoStackIrp) {
        pWriteDataBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
    
        if (pWriteDataBuffer) {                             
			//DbgPrint("Data Written: %s\n", pWriteDataBuffer);
			ICMP_V6_REINJECT_INFO *pReinjectInfo;
			UCHAR action;
			
			pClassificationResult = ExAllocatePoolWithTag(PagedPool, sizeof(USER_MODE_CLASSIFICATION_RESULT), "denS");
			RtlCopyMemory(pClassificationResult, pWriteDataBuffer, sizeof(USER_MODE_CLASSIFICATION_RESULT));
			
			pReinjectInfo = pClassificationResult->pReinjectInfo;
			action = pClassificationResult->action;
			
			//DbgPrint("WRITE: Copied: Address %p, Action: %c\n", pReinjectInfo, action);
			
				
			// Check if pReinjectInfo points to a 
			// reinject info in the global list.
			
			ExAcquireFastMutex(&gListMutex);
	
			pListEntry = gReinjectListHead.Flink;
			while (pListEntry != &gReinjectListHead) {
				ICMP_V6_REINJECT_INFO *pCurrentReinjectInfo = CONTAINING_RECORD(pListEntry, ICMP_V6_REINJECT_INFO, listEntry);
				if (pCurrentReinjectInfo == pReinjectInfo) {
					foundEntry = TRUE;
					break;
				}					
				pListEntry = pListEntry->Flink;
			}
			
			ExReleaseFastMutex(&gListMutex);
	
			if (!foundEntry) {
				//DbgPrint("Error: list entry not found!\n");
				status = STATUS_NO_SUCH_FILE;
			} else {			
				completeClassificationOfPacket(pReinjectInfo, action);
			}
        }
    }
	
	return status;
}


VOID printDataFromNetBufferList(NET_BUFFER_LIST *netBufferList) {
	NET_BUFFER *netBuffer;
	PVOID packetBuf, Ppacket = NULL;
	PUCHAR printPacket;
	UINT packetByteCount, i;
	
	netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
	
	//TODO free packetBuf
	packetBuf = ExAllocatePoolWithTag(PagedPool, NET_BUFFER_DATA_LENGTH(netBuffer), "denS");
	packetByteCount = NET_BUFFER_DATA_LENGTH(netBuffer);
	
	Ppacket = NdisGetDataBuffer(netBuffer,
					  NET_BUFFER_DATA_LENGTH(netBuffer),
					  packetBuf,
					  1,
					  0);
					  
	if (Ppacket == NULL) {
		printPacket = packetBuf;
	} else {
		printPacket = Ppacket;
	}	

	for (i = 0; i < packetByteCount; i++) {
		DbgPrint("%0x ", printPacket[i]);
	}
	DbgPrint("\n");
}

VOID completeClassificationOfPacket(
	ICMP_V6_REINJECT_INFO *pReinjectInfo,
	UCHAR action) 
{	

	switch(action) {
	
	case 'P': 
		//DbgPrint("Packet classified as 'Permit'.\n");
		completeOperationAndReinjectPacket(pReinjectInfo);
		break;

	case 'B':
		//DbgPrint("Packet classified as 'Block'.\n");
		break;	
		
	default:
		//DbgPrint("Packet classified as 'Block' per default.\n");
		break;	
		
	}
	
}

VOID completeOperationAndReinjectPacket(ICMP_V6_REINJECT_INFO *pReinjectInfo) {
	
	NTSTATUS status = NULL;
	
	//DbgPrint("------ Reinjection Function ---------:\n");   
     
	status = FwpsInjectTransportReceiveAsync0(
			pReinjectInfo->injectionHandle,
			NULL,
		    0,
			0,
			AF_INET6,
			pReinjectInfo->compartmentId,
			pReinjectInfo->interfaceIndex,
			pReinjectInfo->subInterfaceIndex,
			pReinjectInfo->netBufferList,
			completionFn,
			pReinjectInfo);
			
	switch (status) {
	case STATUS_SUCCESS:
		DbgPrint("Packet injected successfully.\n");
		break;
	case STATUS_FWP_TCPIP_NOT_READY:
		DbgPrint("Packet cannot be injected: TCPIP is not ready.\n");
		break;
	case STATUS_FWP_INJECT_HANDLE_CLOSING:
		DbgPrint("Packet cannot be injected: Handle is closing.\n");
		break;
	default:
		DbgPrint("Packet cannot be injected: Return value is %0x\n", status);
		break;
	}	
}

VOID NTAPI completionFn(
	VOID *context,
	NET_BUFFER_LIST *netBufferList,
	BOOLEAN dispatchLevel) 
{
	ICMP_V6_REINJECT_INFO *pReinjectInfo = (ICMP_V6_REINJECT_INFO *) context;
	
	ExAcquireFastMutex(&gListMutex);	
	RemoveEntryList(&(pReinjectInfo->listEntry));	
	ExReleaseFastMutex(&gListMutex);

	ExFreePoolWithTag(pReinjectInfo, "denS");
	
	switch (netBufferList->Status) {
	case NDIS_STATUS_SUCCESS:
		DbgPrint("Net Buffer injection was successful.\n");
		break;
	case NDIS_STATUS_INVALID_LENGTH:
		DbgPrint("Net Buffer injection failed: Invalid Length.\n");
		break;
	case NDIS_STATUS_RESOURCES:
		DbgPrint("Net Buffer injection failed: Insufficent ressources.\n");
		break;
	case NDIS_STATUS_FAILURE:
		DbgPrint("Net Buffer injection failed for some reason.\n");
		break;
	case NDIS_STATUS_SEND_ABORTED:
		DbgPrint("Net Buffer injection was aborted.\n");
		break;
	case NDIS_STATUS_RESET_IN_PROGRESS:
		DbgPrint("Net Buffer injection was resetted.\n");
		break;
	case NDIS_STATUS_PAUSED:
		DbgPrint("Net Buffer injection was paused.\n");
		break;
	default:
		DbgPrint("Net Buffer status not recognized: %0x\n", netBufferList->Status);
		break;
	}
	
	FwpsFreeCloneNetBufferList0(netBufferList, 0);
}

NTSTATUS NTAPI TrustrtrNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID  *filterKey,
    IN const FWPS_FILTER1  *filter) 
{
	return STATUS_SUCCESS;	
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	
	FwpsCalloutUnregisterByKey0(&TRUSTRTR_CALLOUT_DRIVER_GUID);
	
	IoDeleteSymbolicLink(&gSymLinkName);
	
	IoDeleteDevice(pDriverObject->DeviceObject);
		
}