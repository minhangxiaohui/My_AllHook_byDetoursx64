#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

const char* pkill = "C:\\Windows\\Temp\\Mydll_HookCreateProcess.dll"; //DLL文件的路径
//char* prosess = "TestMain.exe"; //要注入的进程名(目标进程名)

int main()
{
	HANDLE hSnap;
	HANDLE hkernel32 = NULL; //被注入进程的句柄
	PROCESSENTRY32 pe;
	BOOL bNext;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID Luid;
	LPVOID p;
	FARPROC pfn;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken 失败");
		return 1;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid))
	{

		printf("LookupPrivilegeValue 失败");
		return 1;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = Luid;

	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{

		printf("AdjustTokenPrivileges 失败");
		return 1;
	}

	pe.dwSize = sizeof(pe);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bNext = Process32First(hSnap, &pe);
	char processname[100];

	printf("请输入进程名：");
	scanf("%s", processname);

	printf("输入的进程名是是：%s\n", processname);

	int flag = 1;
	while (bNext)
	{
		//遍历进程名，找要被注入的
		if (!_stricmp(pe.szExeFile, processname))
		{

			hkernel32 = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 1, pe.th32ProcessID);
			flag = 0;
			break;
		}
		bNext = Process32Next(hSnap, &pe);
	}
	if (flag == 1) {
		printf("没找到对应名称的进程");
		return 0;
	}
	CloseHandle(hSnap);
	//拿到远程进程句柄，使用CreateRemoteThread远程进程注入
	p = VirtualAllocEx(hkernel32, NULL, strlen(pkill), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == p)
	{
		printf("开辟空间失败\n");
		return 0;
	}
	
	bool bBol = WriteProcessMemory(hkernel32, p, pkill, strlen(pkill), NULL);
	if (!bBol)
	{
		printf("写dllpath失败");
		return 0 ;
	}
	pfn = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (pfn == NULL) {
		printf("获取loadlibrary失败！");
		return 0;
	}
	HANDLE a = CreateRemoteThread(hkernel32, NULL, 0, (LPTHREAD_START_ROUTINE)pfn, p, NULL, 0);
	if ( a!= NULL)
	{
		printf("注入成功   新进程句柄%d\n" ,a);
	}
	else {
		printf("注入失败");
		return 0;
	}
	// 5.等待线程结束
	WaitForSingleObject(a, -1);

	// 6.清理环境
	VirtualFreeEx(hkernel32, p, 0, MEM_RELEASE);
	CloseHandle(a);
	CloseHandle(hkernel32);
	return 0;
}

