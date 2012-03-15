#ifndef _trustrtr_h
#define _trustrtr_h

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>

typedef struct ICMP_V6_REINJECT_INFO {
	NET_BUFFER_LIST *netBufferList;
	ADDRESS_FAMILY af;
	COMPARTMENT_ID compartmentId;
	IF_INDEX interfaceIndex;
	IF_INDEX subInterfaceIndex;
	HANDLE injectionHandle;
	LIST_ENTRY listEntry;   
	BOOLEAN hasBeenRead;
} ICMP_V6_REINJECT_INFO;

typedef struct USER_MODE_CLASSIFICATION_RESULT {
	ICMP_V6_REINJECT_INFO *pReinjectInfo;
	CHAR action;
} USER_MODE_CLASSIFICATION_RESULT;


VOID NTAPI TrustrtrClassify(
    IN const FWPS_INCOMING_VALUES0  *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0  *inMetaValues,
    IN OUT VOID  *layerData,
	IN const VOID *classifyContext,
    IN const FWPS_FILTER1  *filter,
    IN UINT64  flowContext,
    OUT FWPS_CLASSIFY_OUT0  *classifyOut);

NTSTATUS NTAPI TrustrtrNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID  *filterKey,
    IN const FWPS_FILTER1  *filter);
		
VOID NTAPI cleanUpAfterReinject(
	IN VOID *context,
	IN OUT NET_BUFFER_LIST *netBufferList,
	IN BOOLEAN dispatchLevel);
	
VOID RegisterCallout();

VOID completeClassificationOfPacket(
	ICMP_V6_REINJECT_INFO *pReinjectInfo,
	UCHAR action);
	
VOID reinjectPacket(ICMP_V6_REINJECT_INFO *pReinjectInfo);
VOID removeFromListAndFreePacket(ICMP_V6_REINJECT_INFO *pReinjectInfo);
VOID printDataFromNetBufferList(NET_BUFFER_LIST *netBufferList);
	
NTSTATUS TrustrtrCalloutCreate(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS TrustrtrCalloutWrite(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS TrustrtrCalloutClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS TrustrtrCalloutRead(PDEVICE_OBJECT pDeviceObject, PIRP Irp);

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject);

#define SEND_CALLOUT_BUFFER_SIZE 100
typedef struct _SEND_CALLOUT_DEVICE_EXTENSION {
    CHAR Buffer[SEND_CALLOUT_BUFFER_SIZE];
} SEND_CALLOUT_EXTENSION, *PSEND_CALLOUT_EXTENSION;

#endif