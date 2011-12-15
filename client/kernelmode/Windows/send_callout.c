#include "send_callout.h"

// {252ED6B3-2265-4621-B91A-9EB2C73B45EC}
typedef struct {
	UCHAR *packetData;
	LIST_ENTRY listEntry;
} PACKET_LIST_ENTRY;

typedef struct {
	NET_BUFFER_LIST *netBufferList;
	ADDRESS_FAMILY af;
	COMPARTMENT_ID compartmentId;
	IF_INDEX interfaceIndex;
	IF_INDEX subInterfaceIndex;
	HANDLE aleCompletionContext;
	HANDLE injectionHandle;
   
} ICMP_V6_REINJECT_INFO;

DEFINE_GUID(SEND_CALLOUT_DRIVER, 
0x252ed6b3, 0x2265, 0x4621, 0xb9, 0x1a, 0x9e, 0xb2, 0xc7, 0x3b, 0x45, 0xec);

PCHAR packet = NULL;
LIST_ENTRY packetListHead = {0}; 
DWORD packetByteCount = 0;
UNICODE_STRING symLinkName = {0};
UINT64 classifyHandle = 0;

ICMP_V6_REINJECT_INFO *gReinjectInfo = NULL;

NTSTATUS DriverEntry(
   IN  PDRIVER_OBJECT  pDriverObject,
   IN  PUNICODE_STRING registryPath)
{
	NTSTATUS status;
	UNICODE_STRING usDriverName, usDosDeviceName;
	
	InitializeListHead(&packetListHead);
	
	RtlInitUnicodeString(&usDriverName, L"\\Device\\SendCallout");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\SendCallout");
	
	symLinkName = usDosDeviceName;	
	IoCreateSymbolicLink(&symLinkName, &usDriverName);
	
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
	
	InitializeFilter();
	
	return status;
}

VOID InitializeFilter() 
{
	NTSTATUS status;
	FWPM_FILTER0 fwpFilter;
	FWPM_SUBLAYER0 fwpFilterSubLayer;
	FWPM_FILTER_CONDITION0 fwpConditions[1];
	FWPS_CALLOUT1 sCallout;
	FWPM_CALLOUT0 mCallout;	
	UINT32 CalloutId;
	
	RtlZeroMemory(&fwpFilter, sizeof(FWPM_FILTER0));
	RtlZeroMemory(&sCallout, sizeof(FWPS_CALLOUT1));
	RtlZeroMemory(&mCallout, sizeof(FWPM_CALLOUT0));
	
	sCallout.calloutKey = SEND_CALLOUT_DRIVER;
	sCallout.flags = 0;
	sCallout.classifyFn = ClassifyFn1;
	sCallout.notifyFn = NotifyFn1;
	sCallout.flowDeleteFn = FlowDeleteFn;
	
	status = FwpsCalloutRegister1(
		pDeviceObject,
		&sCallout,
		&CalloutId);
		
	status = FwpmEngineOpen0(
		NULL, 
		RPC_C_AUTHN_WINNT, 
		NULL,
		NULL, 
		&EngineHandle);
	
	mCallout.calloutKey = SEND_CALLOUT_DRIVER;
	mCallout.displayData.name = L"ICMPv6 Router Advertisment callout";
	mCallout.displayData.description = L"Callout driver inspecting all ICMPv6 Router Advertisment";
	mCallout.flags = 0;
	mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;	
	
	status = FwpmCalloutAdd0(
		EngineHandle,
		&mCallout,
		NULL,
		NULL);
	
	fwpConditions[0].fieldKey = FWPM_CONDITION_ORIGINAL_ICMP_TYPE;
	fwpConditions[0].matchType = FWP_MATCH_EQUAL;
	fwpConditions[0].conditionValue.type = FWP_UINT16;
	fwpConditions[0].conditionValue.uint16 = 134; // Router Advertisment code
	
	fwpFilter.numFilterConditions = 1;
	fwpFilter.filterCondition = fwpConditions;	
	fwpFilter.layerKey =  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
	fwpFilter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
	fwpFilter.action.calloutKey = SEND_CALLOUT_DRIVER;
	fwpFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	fwpFilter.weight.type = FWP_EMPTY; // auto-weight.
	fwpFilter.displayData.name = L"ICMPv6 Router Advertisment inspection";
	fwpFilter.displayData.description = L"Callout filter inspecting all ICMPv6 Router Advertisment";

	status = FwpmFilterAdd0(
		EngineHandle,
		&fwpFilter,
		NULL,
		&FilterId);
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
	PCHAR pReturnData = packet;
    UINT dwDataSize = packetByteCount;
	UINT dwDataRead = 0;
	
	if(pReturnData != NULL) {
	//if(!IsListEmpty(&packetListHead)) {
	
		//PLIST_ENTRY plistEntry = RemoveHeadList(&packetListHead);
		//PACKET_LIST_ENTRY *packetListEntry = CONTAINING_RECORD(plistEntry, PACKET_LIST_ENTRY, listEntry);
		
		//pReturnData = packetListEntry->packetData;
		
		pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
		
		if(pIoStackIrp)
		{
			pReadDataBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
			if(pReadDataBuffer && pIoStackIrp->Parameters.Read.Length >= dwDataSize)
			{
				RtlCopyMemory(pReadDataBuffer, pReturnData, dwDataSize);
				dwDataRead = dwDataSize;
				status = STATUS_SUCCESS;
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
			CHAR firstChar = pWriteDataBuffer[0];
			DbgPrint("Data Written: %s\n", pWriteDataBuffer);
			DbgPrint("First char: %c\n", firstChar);
			completeClassificationOfPacket(firstChar);
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
	NET_BUFFER_LIST *clonedNetBufferList = NULL;
	NET_BUFFER *netBuffer;
	int i;
	NTSTATUS status;
	PVOID packetBuf, Ppacket = NULL;
	FWPS_PACKET_INJECTION_STATE injectionState;
	HANDLE injectionHandle = NULL;
	
	//PACKET_LIST_ENTRY *packetListEntry = {0};

	//ExAllocatePoolWithTag(PagedPool, sizeof(PACKET_LIST_ENTRY), "denS");
	
	DbgPrint("Got packet for classification.");
	
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
						
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF || injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}
	
	FwpsAllocateCloneNetBufferList0(
				netBufferList,
				NULL,
				NULL,
				0,
				&clonedNetBufferList);
	
	// At this layer, we are at the beginning of the ICMP payload.
	// We want to go back to the start of the IP-header.
	// NOTE: This adjustment has to be undone before returning from
	// classifyFn1 using NdisAdvanceNetBufferDataStart !
	netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
	
	NdisRetreatNetBufferDataStart(netBuffer,
								  inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize,
								  0,
								  NULL);
								

	packetBuf = ExAllocatePoolWithTag(PagedPool, NET_BUFFER_DATA_LENGTH(netBuffer) + 1, "denS");
	packetByteCount = NET_BUFFER_DATA_LENGTH(netBuffer) + 1;
	
	Ppacket = NdisGetDataBuffer(netBuffer,
					  NET_BUFFER_DATA_LENGTH(netBuffer),
					  packetBuf,
					  1,
					  0);
	
	// NdisGetDataBuffer() can EITHER return a pointer to the packet data
	// OR it can put the data into the buffer provided (packetBuf).
	if (Ppacket == NULL) {
		packet = packetBuf;
	} else {
		packet = Ppacket;
	}
	
	if (packetByteCount >= 97) {
		DbgPrint("Packet Data from Net Buffer (Prefix):");	
		for (i = 80; i < 97; i++) {
			DbgPrint("%0x", packet[i]);
		}
	}
	
	NdisAdvanceNetBufferDataStart(netBuffer,
								  inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize,
								  0,
								  NULL);
					 
	// We want to inspect the packet further in user mode, so absorb and block
	// the packet for the moment. If we want allow it, we have to reinject it later.
	classifyOut->actionType = FWP_ACTION_BLOCK;
	classifyOut->flags = FWPS_CLASSIFY_OUT_FLAG_ABSORB;
	
	// Allocate and populate a ICMP_V6_REINJECT_INFO structure that holds all information
	// necessary to complete the operation and reinject the packet later if necessary.
	// If the decision is made in user mode to permit the packet, this information
	// will be read in completeOperationAndReinjectPacket().
	
	gReinjectInfo = ExAllocatePoolWithTag(PagedPool, sizeof(ICMP_V6_REINJECT_INFO), "denS");
	
	gReinjectInfo->netBufferList = clonedNetBufferList;
	gReinjectInfo->injectionHandle = injectionHandle;
	gReinjectInfo->af = AF_INET6;
	gReinjectInfo->interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_INDEX].value.uint32;
	gReinjectInfo->subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SUB_INTERFACE_INDEX].value.uint32;
	
	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
		gReinjectInfo->compartmentId = inMetaValues->compartmentId;
	} else {
		gReinjectInfo->compartmentId = UNSPECIFIED_COMPARTMENT_ID;
	}
	
	status = FwpsPendOperation0(
			inMetaValues->completionHandle,
			&(gReinjectInfo->aleCompletionContext));
			
	if (status == STATUS_FWP_CANNOT_PEND) {
		DbgPrint("Cannot pend Classify.\n");
	} else if (status == STATUS_SUCCESS) {
		DbgPrint("Packet set to 'pending' successfully.\n");
	} else {
		DbgPrint("Error when trying to pend packet: %0x\n", status);
	}
			
}

void completeClassificationOfPacket(CHAR firstChar) {

	switch(firstChar) {
	
	case 'P': 
		DbgPrint("Packet classified as 'Permit'.\n");
		completeOperationAndReinjectPacket();
		break;

	case 'B':
		DbgPrint("Packet classified as 'Block'.\n");
		FwpsCompleteOperation0(gReinjectInfo->aleCompletionContext, NULL);
		break;	
		
	default:
		DbgPrint("Packet classified as 'Block' per default.\n");
		FwpsCompleteOperation0(gReinjectInfo->aleCompletionContext, NULL);
		break;	
		
	}
		
	
	
}

VOID completeOperationAndReinjectPacket() {


	FwpsCompleteOperation0(gReinjectInfo->aleCompletionContext, gReinjectInfo->netBufferList);
	
	FwpsInjectTransportReceiveAsync0(
			gReinjectInfo->injectionHandle,
			NULL,
		    0,
			0,
			AF_INET6,
			gReinjectInfo->compartmentId,
			gReinjectInfo->interfaceIndex,
			gReinjectInfo->subInterfaceIndex,
			gReinjectInfo->netBufferList,
			completionFn,
			gReinjectInfo);
	
}

VOID NTAPI completionFn(
	VOID *context,
	NET_BUFFER_LIST *netBufferList,
	BOOLEAN dispatchLevel) 
{
	ICMP_V6_REINJECT_INFO *reinjectInfo = (ICMP_V6_REINJECT_INFO *) context;
	
	ExFreePoolWithTag(reinjectInfo, "denS");
	
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
	
	status = FwpmFilterDeleteById0(
		EngineHandle,
		FilterId
	);	
	
	status = FwpmEngineClose0(EngineHandle);
	EngineHandle = NULL;

	
	
	//FwpmCalloutDeleteByKey0(
	//	EngineHandle,
	//	&SEND_CALLOUT_DRIVER
	//);	
	
	status = IoDeleteSymbolicLink(&symLinkName);
	
	IoDeleteDevice(pDriverObject->DeviceObject);
		
}