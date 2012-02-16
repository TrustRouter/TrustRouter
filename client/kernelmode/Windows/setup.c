#include <stdio.h>
#include <windows.h>
#include <fwpmu.h>
#include <initguid.h>
#include <rpc.h>

#pragma comment (lib, "fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")

DEFINE_GUID(SEND_CALLOUT_DRIVER, 
0x252ed6b3, 0x2265, 0x4621, 0xb9, 0x1a, 0x9e, 0xb2, 0xc7, 0x3b, 0x45, 0xec);

int main(int argc, char **args) {
	NTSTATUS status;
	FWPM_CALLOUT0 mCallout;	
	FWPM_FILTER0 bootTimeFilter, persistentFilter;
	HANDLE EngineHandle;
	FWPM_FILTER_CONDITION0 fwpConditions[1];
	UINT64 FilterId;
	FWPM_SUBLAYER0 fwpFilterSubLayer;
	RPC_STATUS rpcStatus = RPC_S_OK;

	
	RtlZeroMemory(&mCallout, sizeof(FWPM_CALLOUT0));
	RtlZeroMemory(&bootTimeFilter, sizeof(FWPM_FILTER0));
	RtlZeroMemory(&persistentFilter, sizeof(FWPM_FILTER0));
	RtlZeroMemory(&fwpFilterSubLayer, sizeof(FWPM_SUBLAYER0));
    rpcStatus = UuidCreate(&fwpFilterSubLayer.subLayerKey);
          
    if (RPC_S_OK != rpcStatus)
    {
		printf("UuidCreate failed (%d).\n", rpcStatus);
		return;
    } else {
		printf("SublayerKey: %d\n", fwpFilterSubLayer.subLayerKey);
	}
	
	fwpFilterSubLayer.displayData.name = L"ICMPv6RASublayer";
    fwpFilterSubLayer.displayData.description = L"ICMPv6 sub-layer for filtering Router Advertisments";
    fwpFilterSubLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    fwpFilterSubLayer.weight = 0x100;
	
	status = FwpmEngineOpen0(
		NULL, 
		RPC_C_AUTHN_WINNT, 
		NULL,
		NULL, 
		&EngineHandle);
		
	if (status == ERROR_SUCCESS) {
		printf("Engine open successful.\n");
	}
	
	status = FwpmSubLayerAdd0(EngineHandle, &fwpFilterSubLayer, NULL);

	if (status != ERROR_SUCCESS)
	{           
		printf("FwpmSubLayerAdd0 failed (%02x).\n", status);
		return;
	}

	mCallout.calloutKey = SEND_CALLOUT_DRIVER;
	mCallout.displayData.name = L"ICMPv6 Router Advertisment callout";
	mCallout.displayData.description = L"Callout driver inspecting all ICMPv6 Router Advertisment packets";
	mCallout.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
	mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;	
	
	status = FwpmCalloutAdd0(
		EngineHandle,
		&mCallout,
		NULL,
		NULL);
		
	if (status == ERROR_SUCCESS) {
		printf("Callout add successful.\n");
	} else {
		printf("Callout add failed: returns %02x\n", status);
	}

	
	fwpConditions[0].fieldKey = FWPM_CONDITION_ORIGINAL_ICMP_TYPE;
	fwpConditions[0].matchType = FWP_MATCH_EQUAL;
	fwpConditions[0].conditionValue.type = FWP_UINT16;
	fwpConditions[0].conditionValue.uint16 = 134; // Router Advertisment code
	
	/*
	 * Create the filter that handles boot-time filtering
	 * until the Base Filtering Engine is loaded.
	 */
	bootTimeFilter.flags = FWPM_FILTER_FLAG_BOOTTIME;
	
	bootTimeFilter.numFilterConditions = 1;
	bootTimeFilter.filterCondition = fwpConditions;	
	bootTimeFilter.layerKey =  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
	bootTimeFilter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	bootTimeFilter.action.calloutKey = SEND_CALLOUT_DRIVER;
	//bootTimeFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	bootTimeFilter.subLayerKey = fwpFilterSubLayer.subLayerKey;
	bootTimeFilter.weight.type = FWP_EMPTY; // auto-weight.
	bootTimeFilter.displayData.name = L"ICMPv6 Router Advertisment inspection";
	bootTimeFilter.displayData.description = L"Boot-time callout filter inspecting all ICMPv6 Router Advertisment";

	status = FwpmFilterAdd0(
		EngineHandle,
		&bootTimeFilter,
		NULL,
		&FilterId);
		
	if (status == ERROR_SUCCESS) {
		printf("Boot time filter add successful, ID: %d\n", FilterId);
	} else {
		printf("Boot time filter add fail: returns %0x\n", status);
	}

	
	/*
	 * Create the filter that handles persistent post 
	 * boot-time filtering after the Base Filtering Engine is loaded.
	 */
	persistentFilter.flags = FWPM_FILTER_FLAG_PERSISTENT;
	
	persistentFilter.numFilterConditions = 1;
	persistentFilter.filterCondition = fwpConditions;	
	persistentFilter.layerKey =  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
	persistentFilter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	persistentFilter.action.calloutKey = SEND_CALLOUT_DRIVER;
	//persistentFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	persistentFilter.subLayerKey = fwpFilterSubLayer.subLayerKey;
	persistentFilter.weight.type = FWP_EMPTY; // auto-weight.
	persistentFilter.displayData.name = L"ICMPv6 Router Advertisment inspection";
	persistentFilter.displayData.description = L"Persistent callout filter inspecting all ICMPv6 Router Advertisment";
	
	status = FwpmFilterAdd0(
		EngineHandle,
		&persistentFilter,
		NULL,
		&FilterId);
		
	if (status == ERROR_SUCCESS) {
		printf("Persistent filter add successful, ID: %d\n", FilterId);
	} else {
		printf("Persistent filter add fail: returns %0x\n", status);		
	}
		
}