#pragma once
#include<Windows.h>
#include<iostream>
#include<Tlhelp32.h>
using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char * lpLibFilename);

using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char * lpProcName);

using f_DLL_ENTRY_POINT = HINSTANCE(WINAPI*)(void * hDll, DWORD dwReason, void * pReserved);

struct Manaual_Mapping_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	HINSTANCE hMod;
	DWORD HijackFuncAddr;
};

void __stdcall ShellCode(Manaual_Mapping_DATA * pData);

bool MaunalMap(HANDLE hProc, const char * szDllfile);

bool InjectDll(const char * szProc, const char * szDllfile);












