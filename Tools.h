#include <Windows.h>
#include <tchar.h>
#include "resource.h"
#include "PE.h"
//����Ȩ��
BOOL EnableDebugPrevilige(BOOL fEnable);
//debug���
void __cdecl OutputDebugStringF(const char* format, ...);



//ö��ģ��
VOID EnumModules(HWND hListProcess, HWND hListProcess2, WPARAM wParam, LPARAM lParam);
//ö�ٽ���
VOID EnumProcess(HWND hListProcess);
//��ʼ�������б�
VOID InitProcessListView2(HWND hDlg);
//��ʼ��ģ���б�
VOID InitProcessListView(HWND hDlg);
//��ʼ������Ŀ¼
VOID InitSectionListView(HWND hDlg);
//��ʼ��Ŀ¼�б�
VOID InitDirectoryView(HWND hDlg);