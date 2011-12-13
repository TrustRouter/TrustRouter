#ifndef _send_callout_h
#define _send_callout_h

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>

UINT64 FilterId;
PDEVICE_OBJECT pDeviceObject;
HANDLE EngineHandle;


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

VOID NTAPI FlowDeleteFn(
    IN UINT16  layerId,
    IN UINT32  calloutId,
    IN UINT64  flowContext);
	
VOID InitializeFilter();
VOID completeClassificationOfPacket(CHAR firstChar);
	
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