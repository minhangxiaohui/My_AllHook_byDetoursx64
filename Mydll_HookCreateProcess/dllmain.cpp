#include "pch.h"
#include<stdio.h>
#include <tlhelp32.h>
#include<detours.h>
#pragma comment(lib,"detours.lib")

VOID __declspec(dllexport)MyFunc() {};

BOOL InjectDll(HANDLE hProcess, LPCTSTR szDllPath)
{

    PROCESSENTRY32 pe;
    BOOL bNext;
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID Luid;
    LPVOID p;
    FARPROC pfn;


    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return 1;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid))
    {
        return 1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid = Luid;

    if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        return 1;
    }

    //拿到远程进程句柄，使用CreateRemoteThread远程进程注入
    p = VirtualAllocEx(hProcess, NULL, strlen(szDllPath), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, p, szDllPath, strlen(szDllPath), NULL);
    pfn = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfn, p, NULL, 0);
    return 0;
}
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL,            
        lpszPrivilege,   
        &luid))         
    {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        return FALSE;
    }

    return TRUE;
}


static BOOL(WINAPI* pCreateProcessA)(
    _In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessA;

static BOOL(WINAPI* pCreateProcessW)(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessW;


BOOL WINAPI My_CreateProcessA(
    _In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation) {

    char text[128];
    //printf(text, "HOOKing！: %s \n", lpApplicationName);
    MessageBoxA(0, "running My_CreateProcessA", "notice", MB_OK);

    // 拦截cmd启动
    //if (strcmp(lpApplicationName, "C:\\Windows\\System32\\cmd.exe") == 0) {
    //    SetLastError(5);
    //    return false;
    //}
    /*
        在自己写的CreateProcessA里面，拿到子进程句柄，对其进行注入
    */
    bool res = pCreateProcessA(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        CREATE_SUSPENDED,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );

   
    //printf("开启新进程，新进程ID为：%d\n", (*lpProcessInformation).dwProcessId);
    //printf("————新进程执行命令参数为：%s\n", lpCommandLine);
    if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
        printf("NewZwResumeThread() : SetPrivilege() failed!!!\n");
    LPCTSTR pkill = "C:\\Windows\\Temp\\Mydll_HookSomeSensitive.dll";
    InjectDll((*lpProcessInformation).hProcess, pkill);
    Sleep(2000);
    //恢复现场
    bool bRet = ResumeThread((*lpProcessInformation).hThread);
    if (bRet == -1)
    {
        printf("ResumeThread 失败 Errcode=%d\n", GetLastError());
    }


    return res;
}
BOOL My_CreateProcessW(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
) {
    char text[128];
    MessageBoxA(0, "running My_CreateProcessW", "notice", MB_OK);

    // 拦截cmd启动
    //if (strcmp(lpApplicationName, "C:\\Windows\\System32\\cmd.exe") == 0) {
    //    SetLastError(5);
    //    return false;
    //}
    /*
        在自己写的CreateProcessA里面，拿到子进程句柄，对其进行注入
    */
    bool res = pCreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        CREATE_SUSPENDED,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
    //printf("开启新进程，新进程ID为：%d\n", (*lpProcessInformation).dwProcessId);
    //printf("————新进程执行命令参数为：%s\n", lpCommandLine);
    if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
        printf("NewZwResumeThread() : SetPrivilege() failed!!!\n");
    LPCTSTR pkill = "C:\\Windows\\Temp\\Mydll_HookSomeSensitive.dll";
    InjectDll((*lpProcessInformation).hProcess, pkill);
    Sleep(2000);
    //恢复现场
    bool bRet = ResumeThread((*lpProcessInformation).hThread);
    if (bRet == -1)
    {
        printf("ResumeThread 失败 Errcode=%d\n", GetLastError());
    }
    return res;
};
void hookfun() {
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    //DetourDetach(&(PVOID&)Real_MessageBoxA, MyMessageBoxA);
    DetourAttach(&(PVOID&)pCreateProcessA, My_CreateProcessA);
    DetourAttach(&(PVOID&)pCreateProcessW, My_CreateProcessW);
    if (0 == DetourTransactionCommit())
    {
        printf("pCreateProcessA、pCreateProcessW hooked succeed\n");
    }
    else
    {
        printf("hook 失败\n");
    }

}
void unhookfun() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    //DetourDetach(&(PVOID&)Real_MessageBoxA, MyMessageBoxA);
    DetourDetach(&(PVOID&)pCreateProcessA, My_CreateProcessA);
    DetourDetach(&(PVOID&)pCreateProcessW, My_CreateProcessW);
    if (0 == DetourTransactionCommit())
    {
        printf("pCreateProcessA、pCreateProcessW unhooked succeed\n");
    }
    else
    {
        printf("unhook 失败\n");
    }
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
        //unhookfun();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

