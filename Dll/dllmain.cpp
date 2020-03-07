// dllmain.cpp : 定义 DLL 应用程序的入口点。
#define _CRT_SECURE_NO_WARNINGS


#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <fstream>
#include <mutex>
#include<Windows.h>
#include<iostream>
#include<Tlhelp32.h>

DWORD ProcessBaseAddr = 0;

DWORD OldFuncAddr;
DWORD HOOKRetAddr;
DWORD PopTarget;

void outputfile(char * buf,int len)
{

	_asm 
	{
		pop PopTarget;
		call OldFuncAddr
		push PopTarget;
	}
	printf("?????????????????????????\n\n\n\n\n\n\n\n");
	//_asm
	//{
	//	jmp HOOKRetAddr;
	//}
	//static std::mutex m;
	//m.lock();
	//std::fstream file("./abc", std::ios::binary | std::ios::app);//打开dll 文件指针定位到文件结尾
	//file << buf << std::endl;
	//file.close();
	//m.unlock();
	//printf(buf);
}


void hookDeCrypt(LPSTR buffer, int len)
{
	_asm
	{
		pop ebp
		pop PopTarget;
		call OldFuncAddr
		push PopTarget;
	}
	printf("%s\n", buffer);
	_asm
	{
		push ebp
	}
}

bool InjectDll(const char * szProc,void *HijackFuncAddr,void * Tmp)
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
	if (!WriteProcessMemory(hProc, HijackFuncAddr, Tmp, 4, nullptr))
	{
		MessageBox(NULL, TEXT("fail"), TEXT("fail"), 0);
	}
	return false;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	static bool flag = false;
	if (!flag)
	{
		//DWORD calladdr = 0x008310F0;
		//WCHAR buffer[64];
		//DWORD OldOffsetFuncAddr = *(DWORD*)(calladdr + 1);
		//OldFuncAddr = OldOffsetFuncAddr + calladdr + 5;
		//DWORD hackaddr = (DWORD)&outputfile;

		//DWORD xaddr = hackaddr - calladdr - 5;
		//InjectDll("Target.exe", (void *)(calladdr + 1), &xaddr);



		DWORD calladdr = 0x00418C1F;
		WCHAR buffer[64];
		DWORD OldOffsetFuncAddr = *(DWORD*)(calladdr + 1);
		OldFuncAddr = OldOffsetFuncAddr + calladdr + 5;
		DWORD hackaddr = (DWORD)&hookDeCrypt;

		DWORD xaddr = hackaddr - calladdr - 5;
		InjectDll("mac_data_server.exe", (void *)(calladdr + 1), &xaddr);

		flag = true;
	}
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		MessageBox(NULL, TEXT("DLL_PROCESS_ATTACH"), TEXT("DLL_PROCESS_ATTACH"),0);
		break;
    case DLL_THREAD_ATTACH:
		MessageBox(NULL, TEXT("DLL_THREAD_ATTACH"), TEXT("DLL_THREAD_ATTACH"), 0);
		break;
    case DLL_THREAD_DETACH:
		MessageBox(NULL, TEXT("DLL_THREAD_ATTACH"), TEXT("DLL_THREAD_ATTACH"), 0);
		break;
    case DLL_PROCESS_DETACH:
		MessageBox(NULL, TEXT("DLL_PROCESS_DETACH"), TEXT("DLL_PROCESS_DETACH"), 0);
        break;
    }
    return TRUE;
}





