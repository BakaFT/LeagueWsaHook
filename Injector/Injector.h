#include <Windows.h>
#include <iostream>
bool SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {

    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

    if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return false;

    // First pass. get current privilege settings
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        &tpPrevious,
        &cbPrevious);

    if (GetLastError() != ERROR_SUCCESS) return false;

    // second pass. set privileges based on previous settings

    tpPrevious.PrivilegeCount = 1;
    tpPrevious.Privileges[0].Luid = luid;

    if (bEnablePrivilege) {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    }
    else {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
    }

    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tpPrevious,
        cbPrevious,
        NULL,
        NULL
    );


    if (GetLastError() != ERROR_SUCCESS) return false;

    return true;
}
int EscalatePrivilege() {

    HANDLE hToken;
    int dwRetVal = 0;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {

        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!ImpersonateSelf(SecurityImpersonation)) return 13;

            if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
                MessageBoxA(NULL, "CAN NOT GOT SYSTEM PERM", "ERROR", MB_OK);
                return 13;
            }

        }
        else {
            return 13;
        }
    }

    // Enable SetPrivilege()

    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {

        MessageBoxA(NULL, "CAN NOT GOT SYSTEM PERM", "ERROR", MB_OK);

        //close token handle
        CloseHandle(hToken);

        //indicate failure
        return 13;
    }

    return dwRetVal;
}

bool InjectPayload(LPCSTR DllPath, HANDLE hProcess) {

	LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	if (!LoadLibAddr) {
		printf("Could note locate real address of LoadLibraryA!\n");
		printf("LastError : 0X%x\n", GetLastError());

		return false;
	}

	printf("LoadLibraryA is located at real address: 0X%p\n", (void*)LoadLibAddr);


	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath), MEM_COMMIT, PAGE_READWRITE);

	if (!pDllPath) {
		printf("Could not allocate Memory in target process\n");
		printf("LastError : 0X%x\n", GetLastError());

		return false;
	}

	printf("Dll path memory allocated at: 0X%p\n", (void*)pDllPath);


	BOOL Written = WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath), NULL);

	if (!Written) {
		printf("Could not write into the allocated memory\n");
		printf("LastError : 0X%x\n", GetLastError());

		return false;
	}

	printf("Dll path memory was written at address : 0x%p\n", (void*)pDllPath);


	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, pDllPath, 0, NULL);

	if (!hThread) {
		printf("Could not open Thread with CreatRemoteThread API\n");
		printf("LastError : 0X%x\n", GetLastError());

		return false;
	}

	printf("Thread started with CreateRemoteThread\n");


	WaitForSingleObject(hThread, INFINITE);


	if (VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE)) {
		//VirtualFreeEx(hProc, reinterpret_cast<int*>(pDllPath) + 0X010000, 0, MEM_RELEASE);
		printf("Memory was freed in target process\n");

	}

	CloseHandle(hThread);

	return true;
}