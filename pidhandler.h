#ifndef PIDHANDLER_H
#define PIDHANDLER_H

#include <windows.h>
#include <tlhelp32.h>
#include <stdbool.h>

// Function to get the process ID (PID) by name
int GetPID(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;  // Failed to create snapshot
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;  // Failed to get the first process
    }

    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return (int)pe32.th32ProcessID;  // Found the process
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;  // Process not found
}

#endif  // PIDHANDLER_H
