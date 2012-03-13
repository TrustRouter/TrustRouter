#include <stdio.h>
#include <windows.h>
#include <fwpmu.h>
#include <stdlib.h>

#pragma comment (lib, "fwpuclnt.lib")

int main(int argc, char **args) {
    NTSTATUS status;
    HANDLE EngineHandle;
    UINT64 id = 0;
    
    if (argc < 2) {
        printf("Expected filter id as argument.\n");
        return 1;
    }
    id = atoi(args[1]);
    
    status = FwpmEngineOpen0(
        NULL, 
        RPC_C_AUTHN_WINNT, 
        NULL,
        NULL, 
        &EngineHandle);
       
    printf("Deleting filter with id %d\n", id);
    status = FwpmFilterDeleteById0(EngineHandle, id);
    
    if (status == ERROR_SUCCESS) {
		printf("Filter removed successfully.\n");
	} else {
		printf("Filter remove failed: returned %02x\n", status);
	}
}