// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include<detours.h>
#include<stdio.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#pragma comment (lib,"detours.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "WinINet.lib")
#pragma warning(disable:4996)
#define ALLOC_THUNK(prototype) __declspec(naked) prototype { _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop _asm nop}	   




typedef BOOL(WINAPI* lpEnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD);
lpEnumProcessModules EnumProcessModules = NULL;

typedef DWORD(WINAPI* lpGetModuleBaseName)(HANDLE, HMODULE, LPCSTR, DWORD);
lpGetModuleBaseName GetModuleBaseName = NULL;


/*

文件：CreateFileA()，WriteFile()，ReadFile()，DeleteFile()
注册表：RegOpenEx()，RegDeleteKey()，RegSetValueEx()，RegCreateKeyEx()
进程：CreateProcess()，ResumeProcess()，CreateRemoteThread()
网络：connect(),InternetConnectA/W(),
*/

VOID __declspec(dllexport)MyFunc1() {};
/*
    原函数缓存
*/
static int (WINAPI* Real_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = MessageBoxA;
static int (WSAAPI* Real_connect)(SOCKET, const sockaddr*, int) = connect;
//static HINTERNET((INTERNETAPI_)* Real_InternetConnectW)(HINTERNET,
//LPCSTR,INTERNET_PORT,LPCSTR,LPCSTR,DWORD,DWORD,DWORD_PTR) = InternetConnectW;
//typedef HINTERNET(STDAPICALLTYPE* FN_INTERNETCONNECTA_DEF)(
//    HINTERNET ,
//    const char* ,
//    INTERNET_PORT ,
//    const char* ,
//    const char* ,
//    DWORD ,
//    DWORD ,
//    DWORD_PTR
//    ) = InternetConnectA;
//ALLOC_THUNK(HINTERNET __stdcall Real_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName OPTIONAL, LPCWSTR lpszPassword OPTIONAL, DWORD dwService, DWORD dwFlags, DWORD dwContext));
//ALLOC_THUNK(HINTERNET __stdcall Real_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName OPTIONAL, LPCSTR lpszPassword OPTIONAL, DWORD dwService, DWORD dwFlags, DWORD dwContext));


/*
    功能函数
*/
// 获取程序pid和程序名
void log_proc_name(void) {

    HMODULE hMod;
    DWORD cbNeeded;
    char buf[255] = { 0 };

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());

    if (hProcess) {

        //_asm int 3

        if (EnumProcessModules == NULL) {
            HMODULE hLib = LoadLibraryA("psapi.dll");
            if (hLib) {
                EnumProcessModules = (lpEnumProcessModules)GetProcAddress(hLib, "EnumProcessModules");
                GetModuleBaseName = (lpGetModuleBaseName)GetProcAddress(hLib, "GetModuleBaseNameA");
            }
        }

        if (EnumProcessModules != NULL && GetModuleBaseName != NULL) {
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                GetModuleBaseName(hProcess, hMod, (char*)buf, 255);
                printf(" **** ProcID: %d = %s ****", GetCurrentProcessId(), buf);
            }
        }

    }

}

//FILE* file;
//fopen_s(&file, "C:meterpreter.txt", "a+");
//SOCKADDR_IN* name_in = (SOCKADDR_IN*)name;
//fprintf(file, "%s : %dn", inet_ntoa(name_in->sin_addr),
// 
//获取调用来自
//__declspec(naked) int CalledFrom() {
//
//    _asm {
//        mov rax, [rbp + 4];
//        ret
//    }
//
//}


/*
    新函数定义
*/
int WINAPI MyMessageBoxA(
    HWND hWnd, LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
) {
    return Real_MessageBoxA(NULL, "run HOOKED MessageBoxA", "NOTICE", MB_OK);
}

int WSAAPI My_connect(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
) {
    //Real_MessageBoxA(NULL, "run HOOKED connect", "NOTICE", MB_OK);
    char ip[128] = {0};
    int port;
    //printf("sa_family_______ %x\nsa_data_______ %x\n",name->sa_family,name->sa_data);
    if (name->sa_family == AF_INET) {
        struct sockaddr_in* my_socket_in = (struct sockaddr_in*)name;
        if (NULL == inet_ntop(AF_INET, (void*)(struct sockaddr*)&my_socket_in->sin_addr, ip, 128))
            printf("获取IP失败，inet_ntop false , WSAGetLastError's returen %d\n", WSAGetLastError());
        port = ntohs(my_socket_in->sin_port);


        printf("调用connect连接IVP4地址，目的地址:%s目的端口:%d\n", ip, port);


        FILE* file;
        // get current dir and
        char* pPath = new char[MAX_PATH];
        GetModuleFileNameA(0, pPath, MAX_PATH);
        pPath[strrchr(pPath, '\\') - pPath + 1] = 0;
        strcat(pPath, "out.txt");
        fopen_s(&file, pPath, "a+");
        fprintf(file, "调用connect连接IVP4地址，目的地址:%s目的端口:%d\n", ip, port);
        fclose(file);

    }
    //黑名单
    //if (strcmp(ip, "74.235.92.151") == 0) {
    //    struct sockaddr_in my_addr;
    //    int my_len = sizeof(struct sockaddr_in);
    //    ZeroMemory(&my_addr, sizeof(my_addr));
    //    my_addr.sin_family = AF_INET;
    //    my_addr.sin_port = htons(80);
    //    my_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    //    return Real_connect(s, (const sockaddr*)&my_addr, sizeof(my_addr));
    //}
    return Real_connect(s, name, namelen);
}
//HINTERNET __stdcall My_InternetConnectA(
//    HINTERNET hInternet,
//    LPCSTR lpszServerName,
//    INTERNET_PORT nServerPort,
//    LPCSTR lpszUserName OPTIONAL,
//    LPCSTR lpszPassword OPTIONAL,
//    DWORD dwService,
//    DWORD dwFlags,
//    DWORD dwContext) {
//
//    log_proc_name();
//
//    if (lpszServerName != NULL) {
//        printf("%d> InternetConnectA: %s", GetCurrentProcessId(), lpszServerName);
//    }
//
//    return Real_InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
//
//}
//HINTERNET __stdcall My_InternetConnectW(
//    HINTERNET hInternet,
//    LPCWSTR lpszServerName,
//    INTERNET_PORT nServerPort,
//    LPCWSTR lpszUserName OPTIONAL,
//    LPCWSTR lpszPassword OPTIONAL,
//    DWORD dwService,
//    DWORD dwFlags,
//    DWORD dwContext) {
//
//    char buf[1500] = { 0 };
//    int i = 0, j = 0;
//    char* tmp = (char*)lpszServerName;
//    log_proc_name();
//
//    //_asm int 3
//
//    while (1) {
//        if (j >= sizeof(buf)) break;
//        if (tmp[i] == 0 && tmp[i + 1] == 0) break;
//        if (tmp[i] != 0) {
//            buf[j] = tmp[i];
//            j++;
//        }
//        i++;
//    }
//    printf("%d> InternetConnectW: %s", GetCurrentProcessId(),  buf);
//
//    return Real_InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
//
//}




void hookfun() {
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_MessageBoxA, MyMessageBoxA);
    DetourAttach(&(PVOID&)Real_connect, My_connect);
    //DetourAttach((PVOID*)&Real_InternetConnectA, My_InternetConnectA);
    //DetourAttach((PVOID*)&Real_InternetConnectW, My_InternetConnectW);
    long a = DetourTransactionCommit();
    printf("DetourTransactionCommit's return %d\n", a);
}
void unhookfun() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_MessageBoxA, MyMessageBoxA);
    DetourDetach(&(PVOID&)Real_connect, My_connect);
    //DetourDetach((PVOID*)&Real_InternetConnectA, My_InternetConnectA);
    //DetourDetach((PVOID*)&Real_InternetConnectW, My_InternetConnectW);
    long a = DetourTransactionCommit();
    //printf("DetourTransactionCommit's return %d\n", a);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hookfun();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

