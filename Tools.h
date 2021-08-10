#include <Windows.h>
#include <tchar.h>
#include "resource.h"
#include "PE.h"
//提升权限
BOOL EnableDebugPrevilige(BOOL fEnable);
//debug输出
void __cdecl OutputDebugStringF(const char* format, ...);



//枚举模块
VOID EnumModules(HWND hListProcess, HWND hListProcess2, WPARAM wParam, LPARAM lParam);
//枚举进程
VOID EnumProcess(HWND hListProcess);
//初始化进程列表
VOID InitProcessListView2(HWND hDlg);
//初始化模块列表
VOID InitProcessListView(HWND hDlg);
//初始化节区目录
VOID InitSectionListView(HWND hDlg);
//初始化目录列表
VOID InitDirectoryView(HWND hDlg);