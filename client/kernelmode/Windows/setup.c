#include <stdio.h>
#include <windows.h>
#include <fwpmu.h>
#include <initguid.h>

#pragma comment (lib, "fwpuclnt.lib")

DEFINE_GUID(SEND_CALLOUT_DRIVER, 
0x252ed6b3, 0x2265, 0x4621, 0xb9, 0x1a, 0x9e, 0xb2, 0xc7, 0x3b, 0x45, 0xec);

int main(int argc, char **args) {
	NTSTATUS status;
	FWPM_CALLOUT0 mCallout;	
	FWPM_FILTER0 bootTimeFilter, persistentFilter;
	HANDLE EngineHandle;
	FWPM_FILTER_CONDITION0 fwpConditions[1];
	UINT64 FilterId;
	
	RtlZeroMemory(&mCallout, sizeof(FWPM_CALLOUT0));
	RtlZeroMemory(&bootTimeFilter, sizeof(FWPM_FILTER0));
	RtlZeroMemory(&persistentFilter, sizeof(FWPM_FILTER0));
	
	status = FwpmEngineOpen0(
		NULL, 
		RPC_C_AUTHN_WINNT, 
		NULL,
		NULL, 
		&EngineHandle);
		
	if (status == ERROR_SUCCESS) {
		printf("Engine open successful.\n");
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
	bootTimeFilter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
	bootTimeFilter.action.calloutKey = SEND_CALLOUT_DRIVER;
	bootTimeFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
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
	}

	
	/*
	 * Create the filter that handles persistent post 
	 * boot-time filtering after the Base Filtering Engine is loaded.
	 */
	persistentFilter.flags = FWPM_FILTER_FLAG_PERSISTENT;
	
	persistentFilter.numFilterConditions = 1;
	persistentFilter.filterCondition = fwpConditions;	
	persistentFilter.layerKey =  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
	persistentFilter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
	persistentFilter.action.calloutKey = SEND_CALLOUT_DRIVER;
	persistentFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
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
	}
		
}