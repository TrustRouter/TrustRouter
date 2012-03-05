#include "send_callout.h"

// {80E84D14-A7DD-4b5f-B5BD-51BCD21EAA49}
DEFINE_GUID(SEND_CALLOUT_DRIVER, 
0x80e84d14, 0xa7dd, 0x4b5f, 0xb5, 0xbd, 0x51, 0xbc, 0xd2, 0x1e, 0xaa, 0x49);

LIST_ENTRY gReinjectListHead = {0}; 
UNICODE_STRING symLinkName = {0};
UINT64 classifyHandle = 0;
PKSPIN_LOCK gSpinLock = NULL;
FAST_MUTEX gListMutex;
UINT k;


NTSTATUS DriverEntry(
   IN  PDRIVER_OBJECT  pDriverObject,
   IN  PUNICODE_STRING registryPath)
{
	NTSTATUS status;
	UNICODE_STRING usDriverName, usDosDeviceName;
	
	RtlInitUnicodeString(&usDriverName, L"\\Device\\SendCallout");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\SendCallout");
	
	symLinkName = usDosDeviceName;	
	IoCreateSymbolicLink(&symLinkName, &usDriverName);
	
	DbgPrint("----------------------------------------------------------------\n");
	
	status = IoCreateDevice(
		pDriverObject,
		0,
		&usDriverName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDeviceObject);
	
	pDriverObject->DriverUnload = DriverUnload;	
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = SendCalloutCreate;
	pDriverObject->MajorFunction[IRP_MJ_READ] = SendCalloutRead;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = SendCalloutClose;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = SendCalloutWrite;
	
	pDeviceObject->Flags = DO_BUFFERED_IO;		
	
	//gSpinLock = ExAllocatePoolWithTag(NonPagedPool, sizeof(KSPIN_LOCK), "denS");
	//KeInitializeSpinLock(gSpinLock);
	ExInitializeFastMutex(&gListMutex);
	
	InitializeListHead(&gReinjectListHead);
	
	InitializeFilter();
	
	return status;
}

VOID InitializeFilter() 
{
	NTSTATUS status;
	
	FWPM_SUBLAYER0 fwpFilterSubLayer;
	FWPS_CALLOUT1 sCallout;
	UINT32 CalloutId;
	
	RtlZeroMemory(&sCallout, sizeof(FWPS_CALLOUT1));
	
	sCallout.calloutKey = SEND_CALLOUT_DRIVER;
	sCallout.flags = 0;
	sCallout.classifyFn = ClassifyFn1;
	sCallout.notifyFn = NotifyFn1;
	sCallout.flowDeleteFn = FlowDeleteFn;
	
	status = FwpsCalloutRegister1(
		pDeviceObject,
		&sCallout,
		&CalloutId);
	
	if (status == STATUS_SUCCESS) {
		DbgPrint("-+-+-+- Callout register was successful.\n");
	} else if (status == STATUS_FWP_ALREADY_EXISTS) {
		DbgPrint("-+-+-+- Callout could not be registered.\n");
	} else {
		DbgPrint("-+-+-+- Callout could not be registered. Status: %0x\n", status);
	}
}

NTSTATUS SendCalloutCreate(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	return STATUS_SUCCESS;
}

NTSTATUS SendCalloutClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	return STATUS_SUCCESS;
}

NTSTATUS SendCalloutRead(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_BUFFER_TOO_SMALL;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
	PCHAR pReadDataBuffer;
	PCHAR pReturnData;
    UINT packetByteCount, returnDataCount;
	UINT dwDataRead = 0;
	UINT totalReadBytes, interfaceId = 0;
	
	//if(pReturnData != NULL) {
	if (!IsListEmpty(&gReinjectListHead)) {
		NET_BUFFER *pNetBuffer;
		PVOID packetBuf, Ppacket = NULL;
		int i;	
		ICMP_V6_REINJECT_INFO *pReinjectInfoToRead = NULL;
		//PLIST_ENTRY plistEntry = RemoveHeadList(&gReinjectListHead, gSpinLock);
		
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
			
			interfaceId = pReinjectInfoToRead->interfaceIndex;
			// Get the packet data from the Net Buffer.
			pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pReinjectInfoToRead->netBufferList);

			packetBuf = ExAllocatePoolWithTag(PagedPool, NET_BUFFER_DATA_LENGTH(pNetBuffer), "denS");
			packetByteCount = NET_BUFFER_DATA_LENGTH(pNetBuffer);
			
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
			
			if(pIoStackIrp)
			{
				pReadDataBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
				totalReadBytes = packetByteCount + sizeof(&interfaceId) + sizeof(pReinjectInfoToRead);
				
				if(pReadDataBuffer && pIoStackIrp->Parameters.Read.Length >= totalReadBytes)
				{
					// First, write the address of the reinject structure into the buffer.
					// It is used to identify the packet when writing back to this driver.
					RtlCopyMemory(pReadDataBuffer, &pReinjectInfoToRead, sizeof(&pReinjectInfoToRead));
					DbgPrint("READ: Copied Address %p to buffer.\n", pReinjectInfoToRead);
					// Now write the interface identifiert, a 32-bit unsigned integer, to the buffer.
					// It is needed as the scope id in userland.
					RtlCopyMemory(pReadDataBuffer + sizeof(&pReinjectInfoToRead), &interfaceId, sizeof(&interfaceId));
					DbgPrint("READ: Copied Interface Identifier %d to buffer.\n", interfaceId);
					// Now, write the byte content of the packet into the buffer.
					RtlCopyMemory(pReadDataBuffer + sizeof(&pReinjectInfoToRead) + sizeof(&interfaceId), pReturnData, packetByteCount);
					DbgPrint("READ: Copied Packet Data to buffer.\n");
					dwDataRead = packetByteCount + sizeof(ICMP_V6_REINJECT_INFO *);
					
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
NTSTATUS SendCalloutWrite(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
    PCHAR pWriteDataBuffer;
	USER_MODE_CLASSIFICATION_RESULT *pClassificationResult;
	UINT i;
	PLIST_ENTRY pListEntry;
	BOOLEAN foundEntry = FALSE;
	
	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	
	if(pIoStackIrp)
    {
        pWriteDataBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
    
        if(pWriteDataBuffer)
        {                             
			/*
			 * We need to verify that the string
			 * is NULL terminated. Bad things can happen
			 * if we access memory not valid while in the Kernel.
			 */
			//DbgPrint("Data Written: %s\n", pWriteDataBuffer);
			ICMP_V6_REINJECT_INFO *pReinjectInfo;
			UCHAR action;
			
			pClassificationResult = ExAllocatePoolWithTag(PagedPool, sizeof(USER_MODE_CLASSIFICATION_RESULT), "denS");
			RtlCopyMemory(pClassificationResult, pWriteDataBuffer, sizeof(USER_MODE_CLASSIFICATION_RESULT));
			
			pReinjectInfo = pClassificationResult->pReinjectInfo;
			action = pClassificationResult->action;
			
			DbgPrint("WRITE: Copied: Address %p, Action: %c\n", pReinjectInfo, action);
			
				
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
				DbgPrint("Error: list entry not found!\n");
				status = STATUS_NO_SUCH_FILE;
			} else {			
				completeClassificationOfPacket(pReinjectInfo, action);
			}
        }
    }
	
	return status;
}


VOID NTAPI ClassifyFn1(
    IN const FWPS_INCOMING_VALUES0  *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0  *inMetaValues,
    IN OUT VOID  *layerData,
	IN const VOID *classifyContext,
    IN const FWPS_FILTER1  *filter,
    IN UINT64  flowContext,
    OUT FWPS_CLASSIFY_OUT0  *classifyOut) 
{
	NET_BUFFER_LIST *netBufferList = (NET_BUFFER_LIST *)layerData;
	NET_BUFFER *netBuffer, *clonedNetBuffer;
	NTSTATUS status;
	PVOID packetBuf, Ppacket = NULL;
	FWPS_PACKET_INJECTION_STATE injectionState;
	HANDLE injectionHandle = NULL;
	NDIS_HANDLE netBufferListPoolHandle;
	PNDIS_GENERIC_OBJECT ndisHandle;
	NET_BUFFER_LIST_POOL_PARAMETERS poolParameters;
	NET_BUFFER_LIST *clonedNetBufferList;
	ICMP_V6_REINJECT_INFO *reinjectInfo;
	int i;
	
	//PACKET_LIST_ENTRY *packetListEntry = {0};

	//ExAllocatePoolWithTag(PagedPool, sizeof(PACKET_LIST_ENTRY), "denS");
	DbgPrint("================== ClassifyFn ============================\n");
	DbgPrint("Got packet for classification.");
    DbgPrint("inMetaValues pointer %p\n", inMetaValues);
    DbgPrint("completionHandle %p\n",  inMetaValues->completionHandle);
    
    //printDataFromNetBufferList(netBufferList);
	
	// Get a handle for injection. Assumption: We only want to inject IPv6 packets.
	status = FwpsInjectionHandleCreate0(
						AF_INET6,
						FWPS_INJECTION_TYPE_TRANSPORT,
						&injectionHandle);
	
	if (status == STATUS_FWP_TCPIP_NOT_READY) {
		DbgPrint("TCPIP stack not ready for injection.\n");
	} else if (status == STATUS_SUCCESS) {
		DbgPrint("Injection handle created successfully.\n");
	} else {
		DbgPrint("Error when trying to get injection handle: %0x\n", status);
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
			DbgPrint("This packet has been injected before. Permitting it.\n");
			return;
	} else {
		DbgPrint("Packet Injection State: %0x\n", injectionState);
	}

	
	// At this layer, we are at the beginning of the ICMP payload.
	// We want to go back to the start of the IP-header.
	// NOTE: This adjustment has to be undone before returning from
	// classifyFn1 using NdisAdvanceNetBufferDataStart !
	netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
	
    
	NdisRetreatNetBufferDataStart(netBuffer,
								  inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize,
								  0,
								  NULL);
	
    
    //DbgPrint("Original Net Buffer List after Retreating to IP Header:\n");
	//printDataFromNetBufferList(netBufferList);
	
	// Make a shallow copy of the net buffer list.
	FwpsAllocateCloneNetBufferList0(
		netBufferList,
		NULL,
		NULL,
		0,
		&clonedNetBufferList);
		
	// FwpsReferenceNetBufferList0(
		// clonedNetBufferList,
		// FALSE);
		
	//DbgPrint("Cloned Net Buffer List after Retreating to IP Header:\n");
	//printDataFromNetBufferList(clonedNetBufferList);
	
    /* 
    if (packetByteCount >= 97) {
        DbgPrint("Packet Data from Net Buffer (Prefix):");	
		for (i = 80; i < 97; i++) {
            DbgPrint("%0x", packet[i]);
		}
	}
    */
    
	
	NdisAdvanceNetBufferDataStart(netBuffer,
								  inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize,
								  0,
                                  NULL);
    /*                          
    DbgPrint("Original Net Buffer List after Advancing to Transport Header:\n");
	printDataFromNetBufferList(netBufferList);
    DbgPrint("Cloned Net Buffer List after Advancing to Transport Header:\n");
	printDataFromNetBufferList(clonedNetBufferList);
	*/
    
    // We want to inspect the packet further in user mode, so absorb and block
	// the packet for the moment. If we want allow it, we have to reinject it later.
	classifyOut->actionType = FWP_ACTION_BLOCK;
	classifyOut->flags = FWPS_CLASSIFY_OUT_FLAG_ABSORB;
	
	// Allocate and populate a ICMP_V6_REINJECT_INFO structure that holds all information
	// necessary to complete the operation and reinject the packet later if necessary.
	// If the decision is made in user mode to permit the packet, this information
	// will be read in completeOperationAndReinjectPacket().
	
	reinjectInfo = ExAllocatePoolWithTag(PagedPool, sizeof(ICMP_V6_REINJECT_INFO), "denS");
	
	reinjectInfo->netBufferList = clonedNetBufferList;
	reinjectInfo->injectionHandle = injectionHandle;
	reinjectInfo->af = AF_INET6;
	reinjectInfo->interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_INDEX].value.uint32;
	DbgPrint("InterfaceIndex is %d\n", reinjectInfo->interfaceIndex);
	reinjectInfo->subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SUB_INTERFACE_INDEX].value.uint32;
	reinjectInfo->hasBeenRead = FALSE;
    	
	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
		reinjectInfo->compartmentId = inMetaValues->compartmentId;
	} else {
		reinjectInfo->compartmentId = UNSPECIFIED_COMPARTMENT_ID;
	}
	
	ExAcquireFastMutex(&gListMutex);	
	InsertTailList(&gReinjectListHead, &(reinjectInfo->listEntry));	
	ExReleaseFastMutex(&gListMutex);
	
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPLETION_HANDLE)) {
        DbgPrint("!!!! CompletionHandle is present -> Pending Operation\n");
        FwpsPendOperation0(
			inMetaValues->completionHandle,
			&(reinjectInfo->aleCompletionContext));	
    } else {
        DbgPrint("???? CompletionHandle is NULL -> Don't Pend!\n");
        reinjectInfo->aleCompletionContext = NULL;
    }
	
    /*
	if (status == STATUS_FWP_CANNOT_PEND) {
		DbgPrint("Cannot pend Classify.\n");
	} else if (status == STATUS_SUCCESS) {
		DbgPrint("Packet set to 'pending' successfully.\n");
	} else if (status == STATUS_FWP_NULL_POINTER) {
		DbgPrint("Invalid parameters for pending. CompletionHandle is: %0x\n", inMetaValues->completionHandle);
	} else if (status == STATUS_FWP_TCPIP_NOT_READY) {
		DbgPrint("TCPIP stack is not ready.\n");
	} else {
		DbgPrint("Error when trying to pend packet: %0x\n", status);
	}
    */
			
	if (!NT_SUCCESS(status)) {
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		if (clonedNetBufferList != NULL) {
			FwpsFreeCloneNetBufferList0(clonedNetBufferList, 0);
		}

		{
		  	ExAcquireFastMutex(&gListMutex);	
			RemoveTailList(&gReinjectListHead);			
			ExReleaseFastMutex(&gListMutex);
		}
	}	

	return;
}

void printDataFromNetBufferList(NET_BUFFER_LIST *netBufferList) {
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

void completeClassificationOfPacket(
	ICMP_V6_REINJECT_INFO *pReinjectInfo,
	UCHAR action) 
{	

	switch(action) {
	
	case 'P': 
		DbgPrint("Packet classified as 'Permit'.\n");
		completeOperationAndReinjectPacket(pReinjectInfo);
		break;

	case 'B':
		DbgPrint("Packet classified as 'Block'.\n");
        if (pReinjectInfo->aleCompletionContext != NULL) {
            // Could be NULL when completionHandle was NULL during classifyFn
            FwpsCompleteOperation0(pReinjectInfo->aleCompletionContext, NULL);
        }
		break;	
		
	default:
		DbgPrint("Packet classified as 'Block' per default.\n");
        if (pReinjectInfo->aleCompletionContext != NULL) {
            // Could be NULL when completionHandle was NULL during classifyFn
            FwpsCompleteOperation0(pReinjectInfo->aleCompletionContext, NULL);
        }
		break;	
		
	}
		
	
	
}

VOID completeOperationAndReinjectPacket(ICMP_V6_REINJECT_INFO *pReinjectInfo) {
	
	NTSTATUS status = NULL;
	
	DbgPrint("------ Reinjection Function ---------:\n");
	//printDataFromNetBufferList(pReinjectInfo->netBufferList);    
     
    if (pReinjectInfo->aleCompletionContext != NULL) {
        // Could be NULL when completionHandle was NULL during classifyFn     
        FwpsCompleteOperation0(pReinjectInfo->aleCompletionContext, pReinjectInfo->netBufferList);
	}
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

NTSTATUS NTAPI NotifyFn1(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID  *filterKey,
    IN const FWPS_FILTER1  *filter) 
{
	return STATUS_SUCCESS;	
}

VOID NTAPI FlowDeleteFn(
    IN UINT16  layerId,
    IN UINT32  calloutId,
    IN UINT64  flowContext)
{
	
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	
	status = FwpsCalloutUnregisterByKey0(&SEND_CALLOUT_DRIVER);
	
	//FwpmCalloutDeleteByKey0(
	//	EngineHandle,
	//	&SEND_CALLOUT_DRIVER
	//);	
	
	status = IoDeleteSymbolicLink(&symLinkName);
	
	IoDeleteDevice(pDriverObject->DeviceObject);
		
}