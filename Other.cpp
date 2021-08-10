#include <Windows.h>
#include <stdio.h>
#include "resource.h"
#include <CommCtrl.h>
#include <TlHelp32.h>
#pragma comment(lib,"comctl32.lib")
#pragma warning(disable: 4996)

BOOL EnableDebugPrevilige(BOOL fEnable)
{
	// Enabling the debug privilege allows the application to see
	// information about service applications
	BOOL fOk = FALSE; // Assume function fails
	HANDLE hToken;

	// Try to open this process's access token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
		&hToken)) {

		// Attempt to modify the "Debug" privilege
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

void __cdecl OutputDebugStringF(const char* format, ...)
{
	va_list vlArgs;
	char* strBuffer = (char*)GlobalAlloc(GPTR, 4096);

	va_start(vlArgs, format);
	_vsnprintf(strBuffer, 4096 - 1, format, vlArgs);
	va_end(vlArgs);
	strcat(strBuffer, "\n");
	OutputDebugStringA(strBuffer);
	GlobalFree(strBuffer);
	return;
}

VOID InitSectionListView(HWND hDlg)
{
	LV_COLUMN lv;
	memset(&lv, 0, sizeof(LV_COLUMN));
	HWND hListProcess;
	hListProcess = GetDlgItem(hDlg, IDC_LIST_SECTION);
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	WCHAR k[] = TEXT("����");
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = k;
	lv.cx = 100;
	lv.iSubItem = 0;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	WCHAR a[] = TEXT("�ڴ�ƫ��");
	lv.pszText = a;
	lv.cx = 100;
	lv.iSubItem = 1;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

	WCHAR b[] = TEXT("�ڴ��С");
	lv.pszText = b;
	lv.cx = 100;
	lv.iSubItem = 2;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 2, (DWORD)&lv);

	WCHAR c[] = TEXT("�ļ�ƫ��");
	lv.pszText = c;
	lv.cx = 100;
	lv.iSubItem = 3;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

	WCHAR d[] = TEXT("�ļ���С");
	lv.pszText = d;
	lv.cx = 100;
	lv.iSubItem = 4;
	ListView_InsertColumn(hListProcess, 4, &lv);

	WCHAR e[] = TEXT("��������");
	lv.pszText = e;
	lv.cx = 100;
	lv.iSubItem = 5;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 5, (DWORD)&lv);

	//EnumProcess(hListProcess);
}


//ö��ģ��
VOID EnumModules(HWND hListProcess, HWND hListProcess2, WPARAM wParam, LPARAM lParam)
{
	//���ǰһ�ε�����µ�����
	ListView_DeleteAllItems(hListProcess);
	DWORD dwRowId;
	TCHAR szPid[0x20];
	LV_ITEM lv;
	memset(&lv, 0, sizeof(LV_ITEM));
	memset(szPid, 0, sizeof(szPid));
	LV_ITEM vitem;
	memset(&vitem, 0, sizeof(LV_ITEM));
	vitem.iItem = 0;
	vitem.iSubItem = 0;
	vitem.mask = LVIF_TEXT;
	//����к�
	dwRowId = SendMessage(hListProcess2, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (dwRowId == -1)
	{
		MessageBox(NULL, TEXT("��ѡ�����"), TEXT("������"), MB_OK);

	}
	//�ڼ���
	lv.iSubItem = 1;
	//�ڼ������������
	lv.pszText = szPid;
	lv.cchTextMax = 0x20;
	SendMessage(hListProcess2, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);
	EnableDebugPrevilige(TRUE);
	//���ֽ�ת���ֽ�
	DWORD dBufSize = WideCharToMultiByte(CP_OEMCP, 0, szPid, -1, NULL, 0, NULL, FALSE);
	char* dBuf = new char[dBufSize];
	memset(dBuf, 0, dBufSize);
	WideCharToMultiByte(CP_OEMCP, 0, szPid, -1, dBuf, dBufSize, NULL, FALSE);
	//Unicode����תΪʮ����
	DWORD i = atoi(dBuf);
	//�������⵼�����һ���ַ���
	//����PID��ֵ ����api�������õ�����ģ��
	HANDLE hModuleSnap;
	MODULEENTRY32 me32;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, i);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		DWORD b = GetLastError();
		OutputDebugStringF("ʧ��%d\n", b);
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		DWORD fff = GetLastError();
		OutputDebugStringF("hModuleSnapʧ��%d\n", fff);
		CloseHandle(hModuleSnap);
	}
	do
	{
		for (vitem.iSubItem = 0; vitem.iSubItem < 2; vitem.iSubItem++)
		{
			if (vitem.iSubItem == 0)
			{

				vitem.pszText = me32.szModule;
				ListView_InsertItem(hListProcess, &vitem);
			}
			if (vitem.iSubItem == 1)
			{
				vitem.pszText = (LPWSTR)me32.szExePath;
				ListView_SetItem(hListProcess, &vitem);
			}
		}
	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);
	delete[]dBuf;
	EnableDebugPrevilige(FALSE);
}

//ö�ٽ���
VOID EnumProcess(HWND hListProcess)
{
	HANDLE hProcessSnap;
	HANDLE hModuleSnap2 = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32;
	MODULEENTRY32 me322;
	LV_ITEM vitem;
	memset(&vitem, 0, sizeof(LV_ITEM));
	vitem.mask = LVIF_TEXT;

	vitem.iItem = 0;
	vitem.iSubItem = 0;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hProcessSnap, &pe32);

	do
	{
		hModuleSnap2 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
		me322.dwSize = sizeof(MODULEENTRY32);
		Module32First(hModuleSnap2, &me322);
		//OutputDebugStringF("modulename:%s\n", me322.szModule);
		for (vitem.iSubItem = 0; vitem.iSubItem < 4; vitem.iSubItem++)
		{


			if (vitem.iSubItem == 0)
			{
				vitem.pszText = (LPWSTR)pe32.szExeFile;
				//wsprintf(vitem.pszText, TEXT("%d%"), pe32.szExeFile);
				SendMessage(hListProcess, LVM_INSERTITEM, 0, (DWORD)&vitem);

			}
			if (vitem.iSubItem == 1)
			{
				wsprintf(vitem.pszText, TEXT("%d%"), pe32.th32ProcessID);
				ListView_SetItem(hListProcess, &vitem);
			}
			if (vitem.iSubItem == 2)
			{
				wsprintf(vitem.pszText, TEXT("%x%"), me322.modBaseAddr);
				ListView_SetItem(hListProcess, &vitem);
			}
			if (vitem.iSubItem == 3)
			{
				wsprintf(vitem.pszText, TEXT("%x%"), me322.modBaseSize);
				ListView_SetItem(hListProcess, &vitem);
			}
		}
		CloseHandle(hModuleSnap2);
		vitem.iItem++;
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
}

//��ʼ��ģ���б�
VOID InitProcessListView(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;
	memset(&lv, 0, sizeof(LV_COLUMN));
	hListProcess = GetDlgItem(hDlg, IDC_LIST_PROCESS);
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	//��һ��
	lv.pszText = TEXT("ģ������");
	lv.cx = 200;
	lv.iSubItem = 0;
	ListView_InsertColumn(hListProcess,0,&lv);
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	// �ڶ���
	lv.pszText = TEXT("ģ��λ��");
	lv.cx = 100;
	lv.iSubItem = 1;
	//ListView_InsertColumn(hListProcess,1,&lv);
	ListView_InsertColumn(hListProcess, 1, &lv);

}

//��ʼ�������б�
VOID InitProcessListView2(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;
	memset(&lv, 0, sizeof(LV_COLUMN));
	//��ȡIDC_LIST_PROCESS���
	hListProcess = GetDlgItem(hDlg, IDC_LIST_PROCESS2);
	//��������ѡ��
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	//��һ��
	
	lv.pszText = TEXT("����");
	lv.cx = 200;
	lv.iSubItem = 0;
	ListView_InsertColumn(hListProcess,0,&lv);
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

	 //�ڶ���
	lv.pszText = TEXT("PID");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess,1,&lv);
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	//������
	lv.pszText = TEXT("�����ַ");
	lv.cx = 100;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess, 2, &lv);
	//������
	lv.pszText = TEXT("�����С");
	lv.cx = 100;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess, 3, &lv);
	EnumProcess(hListProcess);
}

