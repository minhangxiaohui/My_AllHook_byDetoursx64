#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

const char* pkill = "C:\\Windows\\Temp\\Mydll_HookCreateProcess.dll"; //DLL�ļ���·��
//char* prosess = "TestMain.exe"; //Ҫע��Ľ�����(Ŀ�������)

int main()
{
	HANDLE hSnap;
	HANDLE hkernel32 = NULL; //��ע����̵ľ��
	PROCESSENTRY32 pe;
	BOOL bNext;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID Luid;
	LPVOID p;
	FARPROC pfn;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken ʧ��");
		return 1;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid))
	{

		printf("LookupPrivilegeValue ʧ��");
		return 1;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = Luid;

	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{

		printf("AdjustTokenPrivileges ʧ��");
		return 1;
	}

	pe.dwSize = sizeof(pe);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bNext = Process32First(hSnap, &pe);
	char processname[100];

	printf("�������������");
	scanf("%s", processname);

	printf("����Ľ��������ǣ�%s\n", processname);

	int flag = 1;
	while (bNext)
	{
		//��������������Ҫ��ע���
		if (!_stricmp(pe.szExeFile, processname))
		{

			hkernel32 = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 1, pe.th32ProcessID);
			flag = 0;
			break;
		}
		bNext = Process32Next(hSnap, &pe);
	}
	if (flag == 1) {
		printf("û�ҵ���Ӧ���ƵĽ���");
		return 0;
	}
	CloseHandle(hSnap);
	//�õ�Զ�̽��̾����ʹ��CreateRemoteThreadԶ�̽���ע��
	p = VirtualAllocEx(hkernel32, NULL, strlen(pkill), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == p)
	{
		printf("���ٿռ�ʧ��\n");
		return 0;
	}
	
	bool bBol = WriteProcessMemory(hkernel32, p, pkill, strlen(pkill), NULL);
	if (!bBol)
	{
		printf("дdllpathʧ��");
		return 0 ;
	}
	pfn = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (pfn == NULL) {
		printf("��ȡloadlibraryʧ�ܣ�");
		return 0;
	}
	HANDLE a = CreateRemoteThread(hkernel32, NULL, 0, (LPTHREAD_START_ROUTINE)pfn, p, NULL, 0);
	if ( a!= NULL)
	{
		printf("ע��ɹ�   �½��̾��%d\n" ,a);
	}
	else {
		printf("ע��ʧ��");
		return 0;
	}
	// 5.�ȴ��߳̽���
	WaitForSingleObject(a, -1);

	// 6.������
	VirtualFreeEx(hkernel32, p, 0, MEM_RELEASE);
	CloseHandle(a);
	CloseHandle(hkernel32);
	return 0;
}

