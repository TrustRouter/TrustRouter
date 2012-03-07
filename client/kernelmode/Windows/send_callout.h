#ifndef _send_callout_h
#define _send_callout_h

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>

PDEVICE_OBJECT pDeviceObject;

typedef struct ICMP_V6_REINJECT_INFO {
	NET_BUFFER_LIST *netBufferList;
	ADDRESS_FAMILY af;
	COMPARTMENT_ID compartmentId;
	IF_INDEX interfaceIndex;
	IF_INDEX subInterfaceIndex;
	HANDLE aleCompletionContext;
	HANDLE injectionHandle;
	LIST_ENTRY listEntry;   
	BOOLEAN hasBeenRead;
} ICMP_V6_REINJECT_INFO;

typedef struct USER_MODE_CLASSIFICATION_RESULT {
	ICMP_V6_REINJECT_INFO *pReinjectInfo;
	CHAR action;
} USER_MODE_CLASSIFICATION_RESULT;


VOID NTAPI ClassifyFn1(
    IN const FWPS_INCOMING_VALUES0  *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0  *inMetaValues,
    IN OUT VOID  *layerData,
	IN const VOID *classifyContext,
    IN const FWPS_FILTER1  *filter,
    IN UINT64  flowContext,
    OUT FWPS_CLASSIFY_OUT0  *classifyOut);

NTSTATUS NTAPI NotifyFn1(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID  *filterKey,
    IN const FWPS_FILTER1  *filter);
		
VOID NTAPI completionFn(
	IN VOID *context,
	IN OUT NET_BUFFER_LIST *netBufferList,
	IN BOOLEAN dispatchLevel);
	
VOID InitializeFilter();

VOID completeClassificationOfPacket(
	ICMP_V6_REINJECT_INFO *pReinjectInfo,
	UCHAR action);
	
VOID completeOperationAndReinjectPacket(
	ICMP_V6_REINJECT_INFO *pReinjectInfo);
	
void printDataFromNetBufferList(NET_BUFFER_LIST *netBufferList);
	
NTSTATUS SendCalloutCreate(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS SendCalloutWrite(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS SendCalloutClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS SendCalloutRead(PDEVICE_OBJECT pDeviceObject, PIRP Irp);

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject);

#define SEND_CALLOUT_BUFFER_SIZE 100
typedef struct _SEND_CALLOUT_DEVICE_EXTENSION {
    CHAR Buffer[SEND_CALLOUT_BUFFER_SIZE];
} SEND_CALLOUT_EXTENSION, *PSEND_CALLOUT_EXTENSION;

#endif