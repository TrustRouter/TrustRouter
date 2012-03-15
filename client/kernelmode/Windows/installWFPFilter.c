#include <stdio.h>
#include <windows.h>
#include <fwpmu.h>
#include <initguid.h>
#include "installWFPFilter.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment (lib, "fwpuclnt.lib")

// {80E84D14-A7DD-4b5f-B5BD-51BCD21EAA49}
DEFINE_GUID(SEND_CALLOUT_DRIVER, 
0x80e84d14, 0xa7dd, 0x4b5f, 0xb5, 0xbd, 0x51, 0xbc, 0xd2, 0x1e, 0xaa, 0x49);

// {e78a151c-e2fc-44b4-8062-f9949a8f691b}
DEFINE_GUID(ICMPV6_RA_FILTERING_SUBLAYER, 
0xe78a151c, 0xe2fc, 0x44b4, 0x80, 0x62, 0xf9, 0x94, 0x9a, 0x8f, 0x69, 0x1b);

void install_callout_driver() {
    HANDLE hSCManager;
    HANDLE hService;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    
    if (hSCManager != NULL) {
        printf("Create Service\n");
        hService = CreateService(hSCManager, "trustrtr", 
                                 "TrustRouter Callout Driver", 
                                  SERVICE_START | DELETE | SERVICE_STOP, 
                                  SERVICE_KERNEL_DRIVER,
                                  SERVICE_BOOT_START, 
                                  SERVICE_ERROR_NORMAL, 
                                  "\\bin\\i386\\trustrtr.sys",          // Binary path name
                                  "Extended Base",  // Load order group
                                  NULL, NULL, NULL, NULL);
                                  
        if (!hService) {
            printf("Create Service did not work, trying open.\n");
            hService = OpenService(hSCManager, "trustrtr", 
                       SERVICE_START | DELETE | SERVICE_STOP);
        }
        if (hService != NULL) {
            printf("Start Service\n");

            StartService(hService, 0, NULL);

            CloseServiceHandle(hService);            
        } else {
            printf("CreateService failed: %d\n", GetLastError());
        }

        CloseServiceHandle(hSCManager);
    }
}

void install_wfp_filters() {
    NTSTATUS status;
	FWPM_CALLOUT0 mCallout;	
	FWPM_FILTER0 bootTimeFilter, persistentFilter;
	HANDLE EngineHandle;
	FWPM_FILTER_CONDITION0 fwpConditions[2];
	UINT64 FilterId;
	FWPM_SUBLAYER0 fwpFilterSubLayer;

    
	RtlZeroMemory(&mCallout, sizeof(FWPM_CALLOUT0));
	RtlZeroMemory(&bootTimeFilter, sizeof(FWPM_FILTER0));
	RtlZeroMemory(&persistentFilter, sizeof(FWPM_FILTER0));
	RtlZeroMemory(&fwpFilterSubLayer, sizeof(FWPM_SUBLAYER0));
	
	
    fwpFilterSubLayer.subLayerKey = ICMPV6_RA_FILTERING_SUBLAYER;
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
	mCallout.displayData.name = L"ICMPv6 Transport layer Router Advertisment callout";
	mCallout.displayData.description = L"Transport layer inspecting all ICMPv6 Router Advertisment packets";
	mCallout.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
	mCallout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V6;	
	
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
    
    fwpConditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	fwpConditions[0].matchType = FWP_MATCH_EQUAL;
	fwpConditions[0].conditionValue.type = FWP_UINT8;
    fwpConditions[0].conditionValue.uint8 = 58; // ICMPv6
    
  
    fwpConditions[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
	fwpConditions[1].matchType = FWP_MATCH_EQUAL;
	fwpConditions[1].conditionValue.type = FWP_UINT16;
	fwpConditions[1].conditionValue.uint16 = 134; // Router Advertisment
    
    
	/*
	 * Create the filter that handles boot-time filtering
	 * until the Base Filtering Engine is loaded.
	 */
	bootTimeFilter.flags = FWPM_FILTER_FLAG_BOOTTIME;
	
	bootTimeFilter.numFilterConditions = 2;
    bootTimeFilter.filterCondition = fwpConditions;
	bootTimeFilter.layerKey =  FWPM_LAYER_INBOUND_TRANSPORT_V6;
	bootTimeFilter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	bootTimeFilter.action.calloutKey = SEND_CALLOUT_DRIVER;
	//bootTimeFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	bootTimeFilter.subLayerKey = ICMPV6_RA_FILTERING_SUBLAYER;
	bootTimeFilter.weight.type = FWP_EMPTY; // auto-weight.
	bootTimeFilter.displayData.name = L"ICMPv6 Router Adv. Transport layer inspection";
	bootTimeFilter.displayData.description = L"Boot-time callout filter inspecting ICMPv6 Packets at Transport layer";

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
	
	persistentFilter.numFilterConditions = 2;
	persistentFilter.filterCondition = fwpConditions;	
	persistentFilter.layerKey =  FWPM_LAYER_INBOUND_TRANSPORT_V6;
	persistentFilter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	persistentFilter.action.calloutKey = SEND_CALLOUT_DRIVER;
	//persistentFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	persistentFilter.subLayerKey = ICMPV6_RA_FILTERING_SUBLAYER;
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
		printf("Persistent time filter add fail: returns %0x\n", status);
	}
}

int main(int argc, char **args) {

    //install_callout_driver();
    
    install_wfp_filters();		
    
}