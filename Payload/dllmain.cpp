#include "WinSock2.h"
#include "WS2tcpip.h"
#include "Hook.h"
#include "Windows.h"
#pragma comment(lib, "ws2_32.lib")


typedef int (WSAAPI* LPWSACONNECT)(
    SOCKET s,
    const sockaddr* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS
    );

divert div_hook;
LPWSACONNECT fpOriginal;

static int HookedWSAConnect(
    SOCKET s,
    const sockaddr* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS
)
{

    sockaddr_in* data = (sockaddr_in*)(name);
    if (data->sin_port == htons(2099)) {
        data->sin_addr.s_addr = inet_addr("127.0.0.1");
    }

    div_hook.unhook();
    int ret = fpOriginal(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    div_hook.hook(fpOriginal, &HookedWSAConnect);

    return ret;

}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID) {
    if (dwReason == DLL_PROCESS_ATTACH) {

        fpOriginal = reinterpret_cast<LPWSACONNECT>(helper::get_module_export("ws2_32.dll", "WSAConnect"));

        if (fpOriginal) {
            div_hook.hook(fpOriginal, &HookedWSAConnect);
            MessageBoxA(NULL, "WSAConnect Hooked", "Success", MB_OK);
        }
    }
    return TRUE;
}


