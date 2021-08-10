#include <Windows.h>

int ReadPEFile(char* file_path, PVOID* pFileBuffer);
DWORD CopyFileBufferToImageBuffer(HWND hwndDlg, PVOID pFileBuffer, PVOID* pImageBuffer);

DWORD TestPrintDataDirectory(HWND hwndDlg,LPVOID pFileBuffer);

DWORD PrintSection(HWND hListProcess, LPVOID pFileBuffer);
DWORD PrintExportTable(HWND hListProcess, LPVOID pFileBuffer);
DWORD PinrtRelocationTable(HWND hListProcess, LPVOID pFileBuffer);
DWORD WINAPI PrintImportTable(
	LPVOID lpParameter   // thread data		
);

DWORD WINAPI PrintIAT(
	LPVOID lpParameter   
);
DWORD Bound_Import(HWND hListProcess, PVOID pFileBuffer);
DWORD Rsources_File(HWND hListProcess, PVOID pFileBuffer);