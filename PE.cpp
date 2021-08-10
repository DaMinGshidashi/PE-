#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <Windows.h>
#include <CommCtrl.h>
#include <wchar.h>
#include "resource.h"
#pragma comment(lib,"comctl32.lib")
#pragma warning(disable:4996)

typedef struct SParam
{
	HWND hwndDlg;
	PVOID pFileBuffer;
}uParam, * sParam;

int ReadPEFile(char* file_path, PVOID* pFileBuffer)
{
	FILE* pfile = NULL;
	DWORD file_size = 0;
	LPVOID pTempFileBuffer = NULL;
	//���ļ�
	pfile = fopen(file_path, "rb");
	if (!pfile)
	{
		printf("��exe�ļ�ʧ�ܣ�\n");
		return 0;
	}
	//��ȡ��С
	fseek(pfile, 0, SEEK_END);
	file_size = ftell(pfile);
	fseek(pfile, 0, SEEK_SET);

	//����ռ�
	pTempFileBuffer = malloc(file_size);
	if (!pTempFileBuffer)
	{
		printf("����ռ�ʧ��\n");
		fclose(pfile);
		return 0;
	}

	size_t n = fread(pTempFileBuffer, file_size, 1, pfile);
	if (!n)
	{
		printf("���ݶ�ȡ���ڴ���ʧ��!\n");
		fclose(pfile);
		free(pTempFileBuffer);
		return 0;
	}

	//�ر��ļ�
	*pFileBuffer = pTempFileBuffer;
	printf("��ȡ�ļ��ɹ���\n");
	pTempFileBuffer = NULL;
	fclose(pfile);
	return file_size;

}

DWORD RVAtoFOA(PVOID pImageBuffer, DWORD pRVA)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pImageBuffer)
	{
		printf("(RVAת����FOA�׶�)��ȡ���ڴ��pimagebuffer��Ч��\n");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);						// �������ǿ������ת��
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	int image_panyi = pRVA;
	//printf("image_panyi:%x\n", pRVA);
	if (image_panyi < pSectionHeader->PointerToRawData)
	{
		return image_panyi;
	}
	//ѭ���������ĸ�imageBuffer����
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++)
	{
		if ((image_panyi >= pTempSectionHeader->VirtualAddress) && (image_panyi < pTempSectionHeader->VirtualAddress + pTempSectionHeader->Misc.VirtualSize))
		{

			DWORD a = image_panyi - pTempSectionHeader->VirtualAddress + pTempSectionHeader->PointerToRawData;
			//printf("a:%x\n", a);
			return a;
		}
	}
	return 0;

}

DWORD CopyFileBufferToImageBuffer(HWND hwndDlg, PVOID pFileBuffer, PVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	LPVOID pTempImageBuffer = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	pTempImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (!pTempImageBuffer)
	{
		printf("����ʧ�ܣ�\n");
		free(pTempImageBuffer);
		return 0;
	}
	//��ڵ�
	char szBuffer[128];
	sprintf(szBuffer, "%x\n", pOptionHeader->AddressOfEntryPoint);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_EntryPoint, WM_SETTEXT, 0, (DWORD)szBuffer);
	//��ϵͳ
	char szBuffer1[128];
	sprintf(szBuffer1, "%x\n", pOptionHeader->Subsystem);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_SUBSYSTEM, WM_SETTEXT, 0, (DWORD)szBuffer1);
	char szBuffer2[128];
	sprintf(szBuffer2, "%x\n", pOptionHeader->ImageBase);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_BASE, WM_SETTEXT, 0, (DWORD)szBuffer2);
	char szBuffer3[128];
	sprintf(szBuffer3, "%x\n", pPEHeader->NumberOfSections);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_NUMBERSECTION, WM_SETTEXT, 0, (DWORD)szBuffer3);
	char szBuffer4[128];
	sprintf(szBuffer4, "%x\n", pOptionHeader->SizeOfImage);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_IMAGESIZE, WM_SETTEXT, 0, (DWORD)szBuffer4);
	char szBuffer5[128];
	sprintf(szBuffer5, "%x\n", pPEHeader->TimeDateStamp);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_TIMESTAMP, WM_SETTEXT, 0, (DWORD)szBuffer5);
	char szBuffer6[128];
	sprintf(szBuffer6, "%x\n", pOptionHeader->BaseOfCode);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_CODEBASE, WM_SETTEXT, 0, (DWORD)szBuffer6);
	char szBuffer7[128];
	sprintf(szBuffer7, "%x\n", pOptionHeader->SizeOfHeaders);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_SIZEOFHEADER, WM_SETTEXT, 0, (DWORD)szBuffer7);
	char szBuffer8[128];
	sprintf(szBuffer8, "%x\n", pOptionHeader->BaseOfData);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_DATABASE, WM_SETTEXT, 0, (DWORD)szBuffer8);
	char szBuffer9[128];
	sprintf(szBuffer9, "%x\n", pOptionHeader->FileAlignment);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_FILECHARA, WM_SETTEXT, 0, (DWORD)szBuffer9);
	char szBuffer10[128];
	sprintf(szBuffer10, "%x\n", pSectionHeader->PointerToRawData);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_VIRTUALADD, WM_SETTEXT, 0, (DWORD)szBuffer10);
	char szBuffer11[128];
	sprintf(szBuffer11, "%x\n", pOptionHeader->CheckSum);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_CHECKSUM, WM_SETTEXT, 0, (DWORD)szBuffer11);
	char szBuffer12[128];
	sprintf(szBuffer12, "%x\n", pSectionHeader->Misc.PhysicalAddress);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_MISC, WM_SETTEXT, 0, (DWORD)szBuffer12);
	char szBuffer13[128];
	sprintf(szBuffer13, "%x\n", pPEHeader->SizeOfOptionalHeader);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_OPTIONHEADER, WM_SETTEXT, 0, (DWORD)szBuffer13);
	char szBuffer14[128];
	sprintf(szBuffer14, "%x\n", pNTHeader->Signature);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT_MAGIC, WM_SETTEXT, 0, (DWORD)szBuffer14);
	char szBuffer15[128];
	sprintf(szBuffer15, "%x\n", pOptionHeader->DataDirectory);
	SendDlgItemMessageA(hwndDlg, IDC_EDIT16, WM_SETTEXT, 0, (DWORD)szBuffer15);

	//��ʼ����̬�ڴ�
	memset(pTempImageBuffer, 0, pOptionHeader->SizeOfImage);
	//copyͷ��
	memcpy(pTempImageBuffer, pDosHeader, pOptionHeader->SizeOfHeaders);
	//ѭ�������ڱ�
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;

	for (DWORD c = 0; c < pPEHeader->NumberOfSections; c++, pTempSectionHeader++)
	{
		memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress), (void*)((DWORD)pDosHeader + pTempSectionHeader->PointerToRawData), pTempSectionHeader->SizeOfRawData);

	}
	*pImageBuffer = pTempImageBuffer;
	printf("�������ڴ��гɹ���%x\n", pOptionHeader->SizeOfImage);
	pTempImageBuffer = NULL;
	//return pOptionHeader->SizeOfImage;
	free(pFileBuffer);
	return 0;
}

//����Ŀ¼
DWORD TestPrintDataDirectory(HWND hwndDlg,LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	LPCSTR data[16] =
	{
		"������",
		"�����",
		"��Դ��",
		"�쳣��Ϣ��",
		"��ȫ֤���",
		"�ض�λ��",
		"������Ϣ��",
		"��Ȩ��",
		"ȫ��ָ���",
		"TLS��",
		"�������ñ�",
		"�󶨵����",
		"IAT��",
		"�ӳٵ����",
		"����"
	};
	for (int i = 0; i < 16; i++)
	{

		char szBuffer[128];
		char szBuffer2[128];
		sprintf(szBuffer, "%x\n", (pOptionHeader->DataDirectory[i].VirtualAddress));
		sprintf(szBuffer2, "%x\n", (pOptionHeader->DataDirectory[i].Size));
		SendDlgItemMessageA(hwndDlg, IDC_EDIT_RVA1+i, WM_SETTEXT, 0, (DWORD)szBuffer);

		SendDlgItemMessageA(hwndDlg, IDC_EDIT_SIZE1+i, WM_SETTEXT, 0, (DWORD)szBuffer2);
	}
	return 0;
	free(pFileBuffer);

}

//�ڱ���Ϣ
DWORD PrintSection(HWND hListProcess, LPVOID pFileBuffer)
{
	//���ǰһ�ε�����µ�����
	//ListView_DeleteAllItems(hListProcess);
	LV_ITEM vitem;
	memset(&vitem, 0, sizeof(LV_ITEM));
	vitem.iItem = 0;
	vitem.iSubItem = 0;
	vitem.mask = LVIF_TEXT;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		for (vitem.iSubItem = 0; vitem.iSubItem < 6; vitem.iSubItem++)
		{

			if (vitem.iSubItem == 0)
			{
				int sBufSize = strlen((char*)pSectionHeader[i].Name);
				//��ȡ��������С
				//VC++ Ĭ��ʹ��ANSI����ȡ��һ������ΪCP_ACP
				DWORD dBufSize = MultiByteToWideChar(CP_ACP, 0, (LPCCH)pSectionHeader[i].Name, -1, NULL, 0);
				wchar_t* dBuf = new wchar_t[dBufSize];
				wmemset(dBuf, 0, dBufSize);

				//����ת��
				MultiByteToWideChar(CP_ACP, 0, (LPCCH)pSectionHeader[i].Name, sBufSize, dBuf, dBufSize);
				//wsprintf(vitem.pszText, TEXT("%ws"), (pSectionHeader[i].Name));
				vitem.pszText = dBuf;
				SendMessage(hListProcess, LVM_INSERTITEM, 0, (DWORD)&vitem);
			}
			if (vitem.iSubItem == 1)
			{
				wsprintf(vitem.pszText, TEXT("%x"), (pSectionHeader[i].PointerToRawData));
				ListView_SetItem(hListProcess, &vitem);
			}
			if (vitem.iSubItem == 2)
			{
				wsprintf(vitem.pszText, TEXT("%x"), (pSectionHeader[i].SizeOfRawData));
				ListView_SetItem(hListProcess, &vitem);
			}
			if (vitem.iSubItem == 3)
			{
				wsprintf(vitem.pszText, TEXT("%x"), (pSectionHeader[i].VirtualAddress));
				ListView_SetItem(hListProcess, &vitem);
			}
			if (vitem.iSubItem == 4)
			{
				wsprintf(vitem.pszText, TEXT("%x"), (pSectionHeader[i].Misc.VirtualSize));
				ListView_SetItem(hListProcess, &vitem);
			}
			if (vitem.iSubItem == 5)
			{
				wsprintf(vitem.pszText, TEXT("%x"), (pSectionHeader[i].Characteristics));
				ListView_SetItem(hListProcess, &vitem);
			}
		}
		vitem.iItem++;
	}
	return 0;
	free(pFileBuffer);

}

void AppendEdit(HWND hWnd, const char* strOutputString, ...)
{
	HWND hEdit = GetDlgItem(hWnd, IDC_EDIT1);
	char strBuffer[4096] = { 0 };
	va_list vlArgs;
	va_start(vlArgs, strOutputString);
	_vsnprintf_s(strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);
	va_end(vlArgs);

	strcat_s(strBuffer, "\r\n");

	/* �����������Ϊ��edit��׷���ַ��� */
	SendMessageA(hEdit, EM_SETSEL, -2, -1);
	SendMessageA(hEdit, EM_REPLACESEL, true, (long)strBuffer);

	/* ���ù��ֵ�ĩβ�������Ϳ��Կ���������Ϣ */
	SendMessageA(hEdit, WM_VSCROLL, SB_BOTTOM, 0);

}
//��������Ϣ
DWORD PrintExportTable(HWND hListProcess,LPVOID pFileBuffer)
{
	SetWindowText(hListProcess, TEXT(""));

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = \
		(PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[0].VirtualAddress));

	DWORD FOANameAddressDirectory = RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfNames);
	DWORD FOANameOrdinalsDirectory = RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfNameOrdinals);
	DWORD FOAFunctionAddressDirectory = RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfFunctions);
	if (pOptionHeader->DataDirectory[0].Size == 0 && pOptionHeader->DataDirectory[0].VirtualAddress == 0)
	{
		AppendEdit(hListProcess, "û��ʹ�õ�����");
		free(pFileBuffer);
		return 0;
	}
	for (unsigned int i = 0; i < pImageExportDirectory->NumberOfNames; i++)
	{

		AppendEdit(hListProcess, "--------------------------------\r\n");
		DWORD nameAddress = *(DWORD*)((DWORD)pFileBuffer + FOANameAddressDirectory + 4 * i);
		char* pNameAddress = (char*)(nameAddress + (DWORD)pFileBuffer);
		WORD nameOrdinal = *(WORD*)((DWORD)pFileBuffer + FOANameOrdinalsDirectory + 2 * i);
		DWORD functionAddress = *(DWORD*)((DWORD)pFileBuffer + FOAFunctionAddressDirectory + nameOrdinal * 4);
				
		AppendEdit(hListProcess, "�������ƣ���%d����%s\n", i, (char*)pNameAddress);
		AppendEdit(hListProcess, "������ű���%d����%x\n", i, nameOrdinal);
		AppendEdit(hListProcess, "������ַ����%d����%x\n", i, functionAddress);
	}
	return 0;
	free(pFileBuffer);
}

//�ض�λ��
DWORD PinrtRelocationTable(HWND hListProcess,LPVOID pFileBuffer)
{
	SetWindowText(hListProcess, TEXT(""));
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);

	PIMAGE_BASE_RELOCATION pBaseRelocation = \
		(PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[5].VirtualAddress));

	if (pOptionHeader->DataDirectory[5].Size == 0 && pOptionHeader->DataDirectory[5].VirtualAddress == 0)
	{
		AppendEdit(hListProcess, "û��ʹ���ض�λ��");
		free(pFileBuffer);
		return 0;
	}

	while (pBaseRelocation->VirtualAddress || pBaseRelocation->SizeOfBlock)
	{	
		AppendEdit(hListProcess, "===================\r\n");
		AppendEdit(hListProcess, "VirtualAddress = %08x\n", pBaseRelocation->VirtualAddress);
		AppendEdit(hListProcess, "SizeOfBlock = %08x\n", pBaseRelocation->SizeOfBlock);
		PWORD pwAddr = (PWORD)((DWORD)pBaseRelocation + 8);
		int n = (pBaseRelocation->SizeOfBlock - 8) / 2;
		AppendEdit(hListProcess, " ��Ҫ�޸ĵĸ��� = %d\n", n);
		for (int i = 0; i < n; i++)
		{
			WORD wProp = (0xF000 & pwAddr[i]) >> 12;
			WORD wAddr = 0x0FFF & pwAddr[i];
			AppendEdit(hListProcess, "[%d]:RVA = %08x\t���� = %d\n", i + 1, pBaseRelocation->VirtualAddress + wAddr, wProp);
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);

	}
	free(pFileBuffer);
	return 0;
}

//��ӡ�����
DWORD WINAPI PrintImportTable(
	LPVOID lpParameter   // thread data		
)
{
	SParam* test = (SParam*)lpParameter;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)test->pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);

	PIMAGE_IMPORT_DESCRIPTOR pPEImportDescriptor = \
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)test->pFileBuffer + RVAtoFOA(test->pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));
	PDWORD pOriginalFirstThunk = (PDWORD)((DWORD)test->pFileBuffer + RVAtoFOA(test->pFileBuffer, pPEImportDescriptor->OriginalFirstThunk));
	
	while (!( pPEImportDescriptor->OriginalFirstThunk == 0))
	{
		AppendEdit(test->hwndDlg, "\r\n%s", (PBYTE)((DWORD)test->pFileBuffer + RVAtoFOA(test->pFileBuffer, pPEImportDescriptor->Name)));
		AppendEdit(test->hwndDlg, "TimeDataStamp:%x\n", pPEImportDescriptor->TimeDateStamp);
		AppendEdit(test->hwndDlg, "-------------pOriginalFirstThunk--------------\n");
		while (*pOriginalFirstThunk)
		{
			if (*pOriginalFirstThunk & IMAGE_ORDINAL_FLAG32)
			{
				AppendEdit(test->hwndDlg,"����ŵ���:%x\n", (*pOriginalFirstThunk) & 0x0FFF);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImageByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)test->pFileBuffer + RVAtoFOA(test->pFileBuffer, *pOriginalFirstThunk));

				AppendEdit(test->hwndDlg,"�����ֵ���HIN/NAME: %x - %s\n", pImageByName->Hint, pImageByName->Name);
			}	
			pOriginalFirstThunk = (PDWORD)((DWORD)pOriginalFirstThunk + sizeof(IMAGE_THUNK_DATA32));
		}
		pPEImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pPEImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		
	}
	free(test->pFileBuffer);
	return 0;
}

//IAT��
DWORD WINAPI PrintIAT(
	LPVOID lpParameter   // thread data		
)
{
	SParam* test = (SParam*)lpParameter;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)test->pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);

	PIMAGE_IMPORT_DESCRIPTOR pPEImportDescriptor = \
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)test->pFileBuffer + RVAtoFOA(test->pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));	
	
	while (!(pPEImportDescriptor->FirstThunk == 0))
	{
		AppendEdit(test->hwndDlg, "\r\n%s", (PBYTE)((DWORD)test->pFileBuffer + RVAtoFOA(test->pFileBuffer, pPEImportDescriptor->Name)));
		AppendEdit(test->hwndDlg, "-------------pFirstThunkRVA--------------\n");
		PDWORD pFirstThunk = (PDWORD)((DWORD)test->pFileBuffer + RVAtoFOA(test->pFileBuffer, pPEImportDescriptor->FirstThunk));
		AppendEdit(test->hwndDlg, "%x - %x\n", pFirstThunk, *pFirstThunk);
		while (*pFirstThunk)
		{
			if (*pFirstThunk & IMAGE_ORDINAL_FLAG)
			{
				AppendEdit(test->hwndDlg, "������ŵ���:%x\n", (*pFirstThunk) & 0x0fff);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImageByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)test->pFileBuffer + RVAtoFOA(test->pFileBuffer, *pFirstThunk));
				AppendEdit(test->hwndDlg, "�������ֵ���HIN/NAME:%x - %s\n", pImageByName->Hint, pImageByName->Name);
			}
			pFirstThunk = (PDWORD)((DWORD)pFirstThunk + sizeof(IMAGE_THUNK_DATA32));
		}
		pPEImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pPEImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		
	}
	
	free(test->pFileBuffer);
	return 0;
}



//�󶨵����
DWORD Bound_Import(HWND hListProcess, PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_IMPORT_DESCRIPTOR pImport = \
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));

	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptor = \
		(PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[11].VirtualAddress));
	PIMAGE_IMPORT_DESCRIPTOR pPEImportDescriptor = \
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));

	if (pPEImportDescriptor->TimeDateStamp == 0)
	{
		AppendEdit(hListProcess, "û��ʹ�ð󶨵����");
		return 0;
	}

	DWORD dwNameBase = (DWORD)pBoundImportDescriptor;

	while (pBoundImportDescriptor->OffsetModuleName != 0)
	{
		AppendEdit(hListProcess,"OffsetModuleName:%s\n", (PBYTE)((DWORD)dwNameBase + pBoundImportDescriptor->OffsetModuleName));
		AppendEdit(hListProcess,"TimeDateStamp:%x\n", pBoundImportDescriptor->TimeDateStamp);
		AppendEdit(hListProcess,"NumberOfModuleForwarderRefs:%x\n", pBoundImportDescriptor->NumberOfModuleForwarderRefs);
		DWORD  temp = pBoundImportDescriptor->NumberOfModuleForwarderRefs;
		while (temp > 0)
		{
			PIMAGE_BOUND_FORWARDER_REF pBoundImportRef = (PIMAGE_BOUND_FORWARDER_REF)((DWORD)pBoundImportDescriptor + 8);
			pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pBoundImportDescriptor + 8);
			AppendEdit(hListProcess,"    OffsetModuleName:%s\n", (PBYTE)(dwNameBase + pBoundImportDescriptor->OffsetModuleName));
			AppendEdit(hListProcess,"     TimeDateStamp:%x\n", (PBYTE)(pBoundImportDescriptor->TimeDateStamp));

		}
		pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pBoundImportDescriptor + 8 + temp * 8);

	}
	free(pFileBuffer);
	return 0;
}

//��Դ�ļ�
DWORD Rsources_File(HWND hListProcess,PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);

	PIMAGE_RESOURCE_DIRECTORY pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[2].VirtualAddress));
	if (pOptionHeader->DataDirectory[2].Size == 0 && pOptionHeader->DataDirectory[2].VirtualAddress == 0)
	{
		AppendEdit(hListProcess, "û��ʹ����Դ��");
		free(pFileBuffer);
		return 0;
	}
	for (int i = 0; i < pResourceDirectory->NumberOfIdEntries + pResourceDirectory->NumberOfNamedEntries; i++)
	{
		AppendEdit(hListProcess,"--------------------��һ��-----------------\n");
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pRsourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResourceDirectory + 16 + i * 8);
		if (pRsourceEntry->NameIsString)
		{
			PIMAGE_RESOURCE_DIR_STRING_U pRsourceDirStr = (PIMAGE_RESOURCE_DIR_STRING_U)(pRsourceEntry->Name & 0x0fffffff);
			AppendEdit(hListProcess,"���ͣ�%s\n", pRsourceDirStr->NameString);
		}
		else
		{
			AppendEdit(hListProcess,"����:%x\n", pRsourceEntry->Id);
		}
		if (pRsourceEntry->DataIsDirectory )
		{
			//printf("--------------------�ڶ���-------------\n");
			//�õ��ڶ�����
			PIMAGE_RESOURCE_DIRECTORY pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceDirectory + (pRsourceEntry->OffsetToData & 0x0fffffff));
			for (int d = 0; d < pResourceDir2->NumberOfIdEntries + pResourceDir2->NumberOfNamedEntries; d++)
			{
				PIMAGE_RESOURCE_DIRECTORY_ENTRY pRsourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResourceDir2 + 16 + d * 8);
				if (pRsourceEntry2->NameIsString )
				{
					PIMAGE_RESOURCE_DIR_STRING_U pResourceDirStr2 = (PIMAGE_RESOURCE_DIR_STRING_U)(pRsourceEntry->Name & 0x0fffffff);
					AppendEdit(hListProcess,"��Դ����ַ���%x\n", pResourceDirStr2->NameString);
				}
				else
				{
					AppendEdit(hListProcess,"��Դ��ţ�%x\n", pRsourceEntry2->Id);

				}
				if (pRsourceEntry2->DataIsDirectory )
				{
					//���������ҳ
					//printf("------------------������-------------------\n");
					PIMAGE_RESOURCE_DIRECTORY pResourceDir3 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceDirectory + (pRsourceEntry2->OffsetToData & 0x0fffffff));
					for (int s = 0; s < pResourceDir3->NumberOfIdEntries + pResourceDir3->NumberOfNamedEntries; s++)
					{
						PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResourceDir3 + 16 + s * 8);
						if (pResourceEntry3[s].NameIsString)
						{
							PIMAGE_RESOURCE_DIR_STRING_U pResourceDirStr3 = (PIMAGE_RESOURCE_DIR_STRING_U)(pResourceEntry3->Name & 0x0fffffff);
							AppendEdit(hListProcess,"����ҳ��%s\n", pResourceDirStr3->NameString);
						}
						else
						{
							AppendEdit(hListProcess,"����ҳ��%d\n", pResourceEntry3->Id);

						}
						if ((pResourceEntry3->OffsetToData & 0x80000000) != 0x80000000)
						{
							PIMAGE_RESOURCE_DATA_ENTRY pDataDir = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResourceDirectory + (pResourceEntry3->OffsetToData & 0x0fffffff));
							//printf("---------------��С��RVA---------------\n");
							AppendEdit(hListProcess,"Virtual:%x\n", pDataDir->OffsetToData);
							AppendEdit(hListProcess,"Size:%d\n", pDataDir->Size);
						}

					}
				}
			}

		}

	}
	free(pFileBuffer);
	return 0;
}
