#include "MaunalMapInject.h"
#include <fstream>

DWORD ProcessBaseAddr = 0;

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C)==IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C)==IMAGE_REL_BASED_DIR64)
#ifdef _WIN64

#define  RELOC_FLAG RELOC_FLAG64

#else
#define RELOC_FLAG RELOC_FLAG32

#endif // _WIN64

#pragma  optimize("",off)
void __stdcall ShellCode(Manaual_Mapping_DATA * pData)/*Dll表修复硬编码*/
{
	if (!pData)
		return;
	BYTE * pBase = reinterpret_cast<BYTE *> (pData);
	auto * pOpt = &reinterpret_cast<IMAGE_NT_HEADERS *>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;
	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);
	BYTE *LocationDelte = pBase - pOpt->ImageBase;
	if (LocationDelte)
	{
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			auto * pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION *>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress)
			{
				UINT AmouOfEntries = pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD);
				WORD * pRelativeInfo = reinterpret_cast<WORD *>(pRelocData + 1);
				for (size_t i = 0; i < AmouOfEntries; i++, pRelativeInfo)
				{
					if (RELOC_FLAG(*pRelativeInfo))
					{
						UINT_PTR * pPatch = reinterpret_cast<UINT_PTR *>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xfff));
						*pPatch = reinterpret_cast<UINT_PTR>(LocationDelte);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char * szMod = reinterpret_cast<char *>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);
			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);
			if (!pThunkRef)
			{
				pThunkRef = pFuncRef;
			}
			for (; *pThunkRef; pFuncRef++, pThunkRef++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pThunkRef = _GetProcAddress(hDll, reinterpret_cast<char *>(*pThunkRef & 0xffff));

				}
				else
				{
					auto pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);


				}
			}
			++pImportDescr;
		}
	}
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback&&*pCallback; pCallback++)
		{
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}
	*(DWORD*)pBase = pData->HijackFuncAddr;
	for (size_t i = 0x10; i < 0x1000 ; i++)//抹除pe头
	{
		*(pBase+i) = 0;
	}
	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
	
	//void(*func)(char *);
	//func = (void(*)(char *))FuncAddr;
	//func(nullptr);

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
	{
		auto * pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback&&*pCallback; pCallback++)
		{
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	//auto ExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	//DWORD * AddressOfFunctions = (DWORD *)(pBase + ExportDirectory->AddressOfFunctions);
	//WORD  * AddressOfNameOrdinals = (WORD *)(pBase + ExportDirectory->AddressOfNameOrdinals);
	//DWORD * AddressOfNames = (DWORD *)(pBase + ExportDirectory->AddressOfNames);
	//FHijackData * HijackData = reinterpret_cast<FHijackData *>(pBase + 900);
	//for (size_t i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	//{
	//	ExportFunctions[i].VirtualAddress = AddressOfFunctions[i];
	//	ExportFunctions[i].index = i + ExportDirectory->Base;
	//}
	//for (size_t i = 0; i < ExportDirectory->NumberOfNames; i++)
	//{
	//	if(HijackData->HijackFuncName)
	//	ExportFunctions[AddressOfNameOrdinals[i]].name = (char *)(pBase + AddressOfNames[i]);
	//}
	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

#pragma optimize("",on)

bool MaunalMap(HANDLE hProc, const char * szDllfile)
{
	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER * pOldFileHeader = nullptr;
	BYTE * pTargetBase = nullptr;

	if (!GetFileAttributes(szDllfile))
	{
		printf("File doesn't exist \n");
		return false;

	}

	std::ifstream file(szDllfile, std::ios::binary | std::ios::ate);//打开dll 文件指针定位到文件结尾
	if (file.fail())
	{
		printf("opening the file failed %x\n", (DWORD)file.rdstate());
		return false;
	}

	auto filesize = file.tellg();
	if (filesize < 0x1000)
	{
		printf("filesize is invaild\n");
		file.close();
		return false;
	}

	pSrcData = new BYTE[DWORD(filesize)];
	if (!pSrcData)
	{
		printf("pSrcData is invaild\n");
		file.close();
		return false;
	}
	file.seekg(std::ios::beg,0);
	file.read((char *)pSrcData, filesize);
	file.close();
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5a4d)//判断MZ
	{
		printf("invalid file \n");
		delete[]pSrcData;
		return false;
	}
	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;//Opt头位置
	pOldFileHeader = &pOldNtHeader->FileHeader;//file头位置
#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)//检查PE文件的指令类型是不是64位
	{
		printf("Invalid Platform\n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)//检查PE文件的指令类型是不是32位
	{
		printf("Invalid Platform\n");
		delete[] pSrcData;
		return false;
	}
#endif // _WIN64
	pTargetBase = reinterpret_cast<BYTE*>(
		VirtualAllocEx(hProc, reinterpret_cast <void *>(pOldOptHeader->ImageBase),//分配基址
			pOldOptHeader->SizeOfImage,//分配大小
			MEM_COMMIT | MEM_RESERVE,//为特定的页面区域分配内存中或磁盘的页面文件中的物理存储||保留进程的虚拟地址空间，而不分配任何物理存储。保留页面可通过继续调用VirtualAlloc（）而被占用
			PAGE_EXECUTE_READWRITE)//区域包含可执行代码，应用程序可以读写该区域。
		);
	if (!pTargetBase)//如果ImageBase已被占用重新申请
	{
		pTargetBase = reinterpret_cast<BYTE*>(
			VirtualAllocEx(hProc, nullptr,
				pOldOptHeader->SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("Memory allocation failed (ex) 0x%x\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}
	Manaual_Mapping_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	/* 获取函数地址 */

	const char * Section = ".text";
	int Offset = 0x17C1F;
	//int Offset = 0xF0;
	DWORD ReplaceVirtualAddress;
	auto *pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (size_t i = 0; i != pOldFileHeader->NumberOfSections; i++, ++pSectionHeader)
	{
		if (!strcmp((char *)(pSectionHeader->Name), Section))
		{
			ReplaceVirtualAddress = pSectionHeader->VirtualAddress + ProcessBaseAddr;
			printf(" va : %x ", ReplaceVirtualAddress);
			DWORD HijackFuncAddr = ReplaceVirtualAddress + Offset + 1;
			data.HijackFuncAddr = HijackFuncAddr;
		}
	}	
	/* 获取函数地址 */

	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (size_t i = 0; i != pOldFileHeader->NumberOfSections; i++, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
				pSrcData + pSectionHeader->PointerToRawData,
				pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("cant map section : 0x%x \n", GetLastError());
				delete[]  pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, &data, sizeof(data));
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	void * pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pShellcode)
	{
		printf("Memory allocation  fail : 0x%x \n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}
	WriteProcessMemory(hProc, pShellcode, ShellCode, 0x1000, nullptr);//写入手动修复Dll的硬编码


	/*这里debug无效不了 快速编译优化会导致pShellcode位置是一个jmp*/
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);//运行手动修复dll的硬编码
	if (!hThread)
	{
		printf("Thread creation failed  0x%x \n", GetLastError());
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
	}
	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	//while (!hCheck)
	{
		DWORD data_checked;
		ReadProcessMemory(hProc, pTargetBase+0xc, &data_checked, sizeof(data_checked), nullptr);
		printf("%x\n",pTargetBase);
		Sleep(1000);
		ReadProcessMemory(hProc, pTargetBase + 0xc, &data_checked, sizeof(data_checked), nullptr);
		printf("%x ,, ,, ", data_checked);
		ReadProcessMemory(hProc, pTargetBase + 0x10, &data_checked, sizeof(data_checked), nullptr);

		printf("%x ,, ,, ", data_checked);

		if (data_checked)
		{
			DWORD Tmp;
			//char * sp = (char *)&data_checked;
			//char * dp = (char *)&Tmp;
			//for (size_t i = 0; i < 4; i++)
			//{
			//	*(dp + i) = *(sp + 3 - i);
			//}
			//printf("Tmp  %x\n",Tmp);
			//printf("data_checked  %x\n",data_checked);
			Tmp = data_checked - (data.HijackFuncAddr + 4);
			bool success = WriteProcessMemory(hProc, (void *)data.HijackFuncAddr, &Tmp, sizeof(data_checked), nullptr);
			if (success)
			{
				printf("123");
			}
			else 
			{
				printf("456");
			}
		}

		ReadProcessMemory(hProc, pTargetBase + 0x14, &data_checked, sizeof(data_checked), nullptr);
		printf("%x ,, ,, ", data_checked);
		//WriteProcessMemory(hProc, (LPVOID)(ReplaceVirtualAddress + Offset + 2), , 0x1000, nullptr);//劫持call

		if (data_checked)
		{
			return false;
			//break;

		}
	}
	Manaual_Mapping_DATA ModuleBase;
	ReadProcessMemory(hProc, pTargetBase, &ModuleBase, sizeof(Manaual_Mapping_DATA), nullptr);
	printf("\n Module Base : 0x%08x", ModuleBase.hMod);
	printf("\n Maunal Map Inject Success");
	//VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	

	return true;
}


bool InjectDll(const char * szProc, const char * szDllfile)
{
	PROCESSENTRY32 pe32{ 0 };//32位进程入口
	pe32.dwSize = sizeof(pe32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//获取系统所有进程的快照
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		printf("Createtoolhelp32snap fail : 0x%x\n", Err);
		system("pause");
	}
	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &pe32);//从快照中拿出第一个进程
	while (bRet)//遍历进程
	{
		if (!strcmp(szProc, pe32.szExeFile))//匹配进程名
		{
			PID = pe32.th32ProcessID;

			DWORD addressOfChange;//这个因为会变，所有遍历内存中的模块
			HANDLE phSnapshot;
			MODULEENTRY32 me32;//存放快照信息的结构体
			phSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);//创建进程快照
			if (phSnapshot == INVALID_HANDLE_VALUE)
			{
				return false;
			}
			//使用之前先设置大小    0x00750000
			me32.dwSize = sizeof(MODULEENTRY32);
			if (!Module32First(phSnapshot, &me32))
			{
				return false;
			}
			do
			{
				if (!strcmp(szProc, me32.szModule))//匹配进程名
				{
					if (me32.th32ProcessID == PID)
					{
						ProcessBaseAddr = (DWORD)me32.modBaseAddr;
						break;
					}
				}
			} while (Module32Next(phSnapshot, &me32));
			break;
		}
		bRet = Process32Next(hSnap, &pe32);
	}
	CloseHandle(hSnap);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);//通过PID获取进程句柄
	return MaunalMap(hProc, szDllfile);
}



void main()
{
	bool OK = InjectDll("mac_data_server.exe", "C:\\Users\\dmz\\Desktop\\studyproject\\InjectDll\\Release\\InjectDll.dll");
	printf("Injectdll : %d \n" , OK);
	while (1);
}
