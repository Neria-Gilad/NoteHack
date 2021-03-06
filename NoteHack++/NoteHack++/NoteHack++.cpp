#include <Windows.h>
#include<TlHelp32.h>
#include <CommCtrl.h>
#include <tchar.h>
#include "resource.h"
#include <string>

#pragma comment(linker, \
  "\"/manifestdependency:type='Win32' "\
  "name='Microsoft.Windows.Common-Controls' "\
  "version='6.0.0.0' "\
  "processorArchitecture='*' "\
  "publicKeyToken='6595b64144ccf1df' "\
  "language='*'\"")

#pragma comment(lib, "ComCtl32.lib")
#ifndef SW_SHOW 
#define SW_SHOW 5
#endif
#ifndef SW_HIDE 
#define SW_HIDE 0
#endif

DWORD FindProcessId(const std::string& processName);
bool InjectDLL(const DWORD pId, LPWSTR dllPathWIDE);
void hack();

INT_PTR CALLBACK WinProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
void onCancel(HWND hDlg);
void onClose(HWND hDlg);

int WINAPI _tWinMain(HINSTANCE hInst, HINSTANCE h0, LPTSTR lpCmdLine, int nCmdShow) {
	MSG msg;
	BOOL ret;

	InitCommonControls();
	HWND hDlg = CreateDialogParam(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), nullptr, WinProc, 0);
	ShowWindow(hDlg, SW_SHOW);

	while (ret = GetMessage(&msg, nullptr, 0, 0)) {
		if (ret == -1)
			return -1;
		if (!IsDialogMessage(hDlg, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	return 0;
}


void onCancel(HWND hDlg) {
	SendMessage(hDlg, WM_CLOSE, 0, 0);
}
void onClose(HWND hDlg) {
#ifdef ___OPTIONAL___
	if (MessageBox(hDlg, TEXT("Close the program?"), TEXT("Close"),
				   MB_ICONQUESTION | MB_YESNO) == IDYES) {
		DestroyWindow(hDlg);
	}
#else
	DestroyWindow(hDlg);
#endif
}
INT_PTR CALLBACK WinProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDCANCEL:
					onCancel(hDlg);
					break;
				case IDOK:
					hack();
					DestroyWindow(hDlg);
					break;
			}
			break;
		case WM_CLOSE:
			onClose(hDlg);
			break;
		case WM_DESTROY:
			PostQuitMessage(0);
			return TRUE;
	}
	return FALSE;
}


void hack() {
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	si.cb = sizeof(si);
	if (!CreateProcess(TEXT("C:\\WINDOWS\\system32\\cmd.exe"), (LPWSTR)TEXT("/c start notepad++"), nullptr, nullptr, FALSE,
					   0, 0, 0, &si, &pi)) {
		/* Handle error */
		MessageBoxA(0, "something went wrong. please open notepad++ and press ok", 0, 0);
	}
	//Sleep(10000);
	WaitForSingleObject(pi.hProcess, 15000);
	auto dllPath = TEXT("inject_this.dll");
	char* dllp = new char[256];// [128];
	GetFullPathName(dllPath,
					128,
					(LPWSTR)dllp, //Output to save the full DLL path
					NULL);
	InjectDLL(FindProcessId("notepad++.exe"), (LPWSTR)dllp);

}

DWORD FindProcessId(const std::string& processName) {
	PROCESSENTRY32 processInfo;
	DWORD processFound;
	processInfo.dwSize = sizeof(processInfo);
	bool found = false;
	const HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) return 0;

	Process32First(processesSnapshot, &processInfo);

	//convert from wide char to narrow char array
	char ch[260];
	char DefChar = ' ';

	do {
		WideCharToMultiByte(CP_ACP, 0, processInfo.szExeFile, -1, ch, 260, &DefChar, nullptr);
		if (!processName.compare(std::string(ch))) {
			found = true;
			processFound = processInfo.th32ProcessID;
			//////////////////////////////////////////////////////////
			//these if you want to find the first notepad++ opened  //
			//CloseHandle(processesSnapshot);						//
			//return processInfo.th32ProcessID;						//
			//////////////////////////////////////////////////////////
		}
	} while (Process32Next(processesSnapshot, &processInfo));
	CloseHandle(processesSnapshot);
	if (found)
		return processFound;
	return 0;
}

bool InjectDLL(const DWORD pId, LPWSTR dllPathWIDE) {
	int length = WideCharToMultiByte(CP_ACP, 0, dllPathWIDE, -1, 0, 0, NULL, NULL);
	char* dllPath = new char[length];
	WideCharToMultiByte(CP_ACP, 0, dllPathWIDE, -1, dllPath, length, NULL, NULL);


	const HANDLE htargetP = OpenProcess(PROCESS_ALL_ACCESS, 0, pId);
	if (!htargetP) return false;

	LPVOID loadAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	LPVOID LoadPath = VirtualAllocEx(htargetP, 0, strlen(dllPath),
									 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(htargetP, LoadPath, dllPath, strlen(dllPath), NULL);
	HANDLE RemoteThread = CreateRemoteThread(htargetP, 0, 0,
		(LPTHREAD_START_ROUTINE)loadAddr, LoadPath, 0, 0);
	WaitForSingleObject(RemoteThread, INFINITE);
	VirtualFreeEx(htargetP, LoadPath, strlen(dllPath), MEM_RELEASE);
	CloseHandle(RemoteThread);
	CloseHandle(htargetP);
	return true;
}