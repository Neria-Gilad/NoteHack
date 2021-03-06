//	dllmain.cpp : Defines the entry point for the DLL application.
//	Works for Notepad++ v7.51 (32-bit)

#include "stdafx.h"
#include "HookFunctions.h"


INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {

	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, MainThread, hDLL, 0, 0);
		break;
	case DLL_PROCESS_DETACH:   // probably useless
	case DLL_THREAD_ATTACH:	   // probably useless
	case DLL_THREAD_DETACH:	   // probably useless
		break;
	}

	return TRUE;
}
