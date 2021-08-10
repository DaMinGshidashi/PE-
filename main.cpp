#include <Windows.h>
#include <stdio.h>
#include <CommCtrl.h>
#include  "resource.h"
#include "Tools.h"
#include "PE.h"
#pragma comment(lib,"comctl32.lib")
#pragma warning(disable: 4996)
HINSTANCE ApphInst;
OPENFILENAMEA stOpenFile;

typedef struct SParam
{
	HWND hwndDlg;
	PVOID pFileBuffer;
}uParam, * sParam;
//导出表

BOOL CALLBACK ProcDlgALL(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		PVOID pFileBuffer; 
		DWORD OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);
		PrintExportTable(hwndDlg, pFileBuffer);
		break;
		
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}

	}
	return bRet;
}
//导入表
BOOL CALLBACK ProcDlgALL1(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		PVOID pFileBuffer;
		DWORD OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);
		SParam* pParam = new  SParam;
		pParam->hwndDlg = hwndDlg;
		pParam->pFileBuffer = pFileBuffer;
		HANDLE hThread = CreateThread(NULL, 0, PrintImportTable, pParam, 0, NULL);
		CloseHandle(hThread);
		//delete pParam;
		break;

	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}

	}
	return bRet;
}
//资源表
BOOL CALLBACK ProcDlgALL2(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		PVOID pFileBuffer;
		DWORD OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);
		Rsources_File(hwndDlg, pFileBuffer);
		break;

	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}

	}
	return bRet;
}
//重定位表
BOOL CALLBACK ProcDlgALL3(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		PVOID pFileBuffer;
		DWORD OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);
		PinrtRelocationTable(hwndDlg, pFileBuffer);
		break;

	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}

	}
	return bRet;
}
//绑定导入表
BOOL CALLBACK ProcDlgALL4(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		PVOID pFileBuffer;
		DWORD OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);
		Bound_Import(hwndDlg, pFileBuffer);
		
		break;

	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}

	}
	return bRet;
}

//IAT表
BOOL CALLBACK ProcDlgALL5(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		PVOID pFileBuffer;
		DWORD OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);
		SParam* pParam1 = new SParam;
		pParam1->hwndDlg = hwndDlg;
		pParam1->pFileBuffer = pFileBuffer;

		HANDLE hThread = CreateThread(NULL, 0, PrintIAT, pParam1, 0, NULL);
		CloseHandle(hThread);
		break;

	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}

	}
	return bRet;
}

//目录查看
BOOL CALLBACK ProcDlgDirctory(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}
	case WM_INITDIALOG:
	{
		PVOID pFileBuffer;
		DWORD OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);
		TestPrintDataDirectory(hwndDlg, pFileBuffer);
		break;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_OUTDIR:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_ALL), hwndDlg, (DLGPROC)ProcDlgALL);
			return true;
		}
		case IDC_BUTTON_IMPDIR:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_ALL), hwndDlg, (DLGPROC)ProcDlgALL1);
			return true;
		}
		case IDC_BUTTON_RESDIR:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_ALL), hwndDlg, (DLGPROC)ProcDlgALL2);
			return true;
		}
		case IDC_BUTTON_BASERELOC:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_ALL), hwndDlg, (DLGPROC)ProcDlgALL3);
			return true;
		}
		case IDC_BUTTON_BIND:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_ALL), hwndDlg, (DLGPROC)ProcDlgALL4);
			return true;
		}
		case IDC_BUTTON_IAT:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_ALL), hwndDlg, (DLGPROC)ProcDlgALL5);
			return true;
		}
		}
	}
	}
	return bRet;
}

//节表查看
BOOL CALLBACK ProcDlgSection(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}
	case WM_INITDIALOG:
	{
		InitSectionListView(hwndDlg);
		PVOID pFileBuffer;
		DWORD OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);

		PrintSection(GetDlgItem(hwndDlg, IDC_LIST_SECTION),pFileBuffer);
		break;
	}
	}
	return bRet;

}

//PE查看
BOOL CALLBACK ProcDlgPE(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}
	case WM_INITDIALOG:
	{
		PVOID pFileBuffer;
		PVOID pImageBuffer;
		DWORD OpenFile;
		OpenFile = ReadPEFile(stOpenFile.lpstrFile, &pFileBuffer);
		if (OpenFile)
		{
			CopyFileBufferToImageBuffer(hwndDlg, pFileBuffer, &pImageBuffer);
		}
		break;

	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_CLOSE:
		{
			EndDialog(hwndDlg, 0);
			break;
		}
		case IDC_BUTTON_DIRECTORY:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_DIRCTORY), hwndDlg, (DLGPROC)ProcDlgDirctory);
			break;
		}
		case IDC_BUTTON_SECTION:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_SECTION), hwndDlg, (DLGPROC)ProcDlgSection);
			break;
		}

		}
	}
	}
	return bRet;
}

//关于
BOOL CALLBACK ProcDlgPEABOUT(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
	)
{
	BOOL bRet = FALSE;
	switch (uMsg)
	{
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}
	}
	return bRet;
}

//主程序入口
BOOL CALLBACK DialogProc(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
)
{
	BOOL bRet = FALSE;

	HWND hEditUser = NULL;
	HWND hEditPass = NULL;
	HICON BighIcon = NULL;
	switch (uMsg)
	{
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}
	case WM_NOTIFY:
	{
		NMHDR* pNMHDR = (NMHDR*)lParam;
		if (wParam == IDC_LIST_PROCESS2 && pNMHDR->code == NM_CLICK)
		{
			EnumModules(GetDlgItem(hwndDlg, IDC_LIST_PROCESS),GetDlgItem(hwndDlg, IDC_LIST_PROCESS2), wParam, lParam);
		}
		break;
	}
	case WM_INITDIALOG:
	{
		//加载图标
		HICON hIcon = LoadIcon(ApphInst, MAKEINTRESOURCE(IDI_ICON));
		SendMessage(hwndDlg, WM_SETICON, FALSE, (LPARAM)hIcon);
		SendMessage(hwndDlg, WM_SETICON, TRUE, (LPARAM)hIcon);
		InitProcessListView2(hwndDlg);
		InitProcessListView(hwndDlg);
		return TRUE;
	}
	
	case WM_COMMAND:
		switch (LOWORD(wParam)) {

		case IDC_BUTTON_PE:
		{
			CHAR szPeFileExit[100] = "*.exe;*.dll;*.scr;*.drv;*.sys";
			CHAR szFileName[256];
			memset(szFileName, 0, 256);
			memset(&stOpenFile, 0, sizeof(OPENFILENAMEA));
			stOpenFile.lStructSize = sizeof(OPENFILENAMEA);
			stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			stOpenFile.hwndOwner = hwndDlg;
			stOpenFile.lpstrFilter = szPeFileExit;
			stOpenFile.lpstrFile = szFileName;
			stOpenFile.nMaxFile = MAX_PATH;
			GetOpenFileNameA(&stOpenFile);

			//MessageBoxA(0, stOpenFile.lpstrFile, 0, 0);
			DialogBox(ApphInst,MAKEINTRESOURCE(IDD_DIALOG_PE), hwndDlg, (DLGPROC)ProcDlgPE);
			return FALSE;
		}
		case IDC_BUTTON_about:
		{
			DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_PEABOUT), hwndDlg, (DLGPROC)ProcDlgPEABOUT);
			return TRUE;
		}
		case IDC_BUTTON_EXIT:
		{
			EndDialog(hwndDlg, 0);

			return TRUE;
		}
		}
		break;
	}
	return bRet;
}

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
	OPENFILENAME stOpenFile;
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);
	HINSTANCE ApphInst = hInst;
	DialogBox(ApphInst, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, (DLGPROC)DialogProc);
}