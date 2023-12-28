#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include "Injector.h"

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_wcsicmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    const wchar_t* processName = L"LeagueClient.exe";
    bool processFound = 0;
    int32_t pid = 0;

    int epResult = EscalatePrivilege();
    if (epResult == 0)
        printf("Successfully Escalated privileges to SYSTEM level...\n");

    while (!processFound) {
        pid = GetProcessIdByName(processName);
        if (pid == 0) {
            Sleep(100);  // Sleep for 100ms
            continue;
        }
        processFound = 1;
        printf("Found LeagueClient.exe PID: %d\n", pid);
        // This path should be relative to `LeagueClient.exe` or use absolute path directly
        InjectPayload("D:\\myMsg.dll", OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
    }

    return 0;
}


