//******************************************************************//
//					includes & macros
//******************************************************************//
#pragma once
#if defined(UNICODE) && !defined(_UNICODE)
#define _UNICODE
#elif defined(_UNICODE) && !defined(UNICODE)
#define UNICODE
#endif
 
#include <tchar.h>
#include <windows.h>
#ifndef SW_SHOW 
#define SW_SHOW 5
#endif
#ifndef SW_HIDE 
#define SW_HIDE 0
#endif

#define CCHMAX 200
#define  BASE_FREME_STATIC_TEXT_LEN 17
#define  BASE_FREME_INPUT_TEXT_LEN 207
#define  X_STEP 40
#define  Y_STEP 40
#define  X_STATIC_TEXT_LEN 375
#define  Y_STATIC_TEXT_LEN 40
#define  X_INPUT_TEXT_LEN 190
#define  Y_INPUT_TEXT_LEN 28

#define  X_BUTTON_SIZE 70
#define  Y_BUTTON_SIZE 27
 
#define  WINDOW_WIDTH  415 // X axis for dummies like me
#define  WINDOW_HEIGHT 250 // Y axis for dummies like me

//******************************************************************//
//					declerations
//******************************************************************//
LRESULT CALLBACK EnterNewPasswordProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK EnterUpdatePasswordProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK EnterPasswordProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
void onCancel(HWND hDlg);
void onClose(HWND hDlg);
void gui_updatePassword();
void gui_createPassword(char* &newPass);
void gui_enterPassword(char *& newPass, char *& oldPass);
char pass_new[CCHMAX];
char pass_new2[CCHMAX];
char pass_old[CCHMAX];
void zeroize();

//******************************************************************//
//					global fields
//******************************************************************//
enum WINWODS_FIELDS {
	STATICTEXT = 1,
	OLD_PASS_STATICTEXT,
	NEW_PASS_STATICTEXT,
	NEW2_PASS_STATICTEXT,
	OLD_PASS_INPUT,
	NEW_PASS_INPUT,
	NEW2_PASS_INPUT,
	BUTTON_OK,
	BUTTON_CANCEL,
	IDOK_CNGPASS,
};
HWND TextBox, SendButton, TextField,
staticText, oldPass_staticText, newPass_staticText, newPass2_staticText,
oldPass_input, newPass_input, newPass2_input,
ok_button, cancel_button;

//******************************************************************//
//					implementations
//******************************************************************//
LRESULT CALLBACK EnterUpdatePasswordProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_CREATE:
#pragma region WINDOW_CREATION
			/******** Static texts ********/
			staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("Choose a good one this time"),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN, X_STATIC_TEXT_LEN, Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)STATICTEXT, NULL, NULL
			);

			oldPass_staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("Enter old password: "),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + Y_STEP, X_STATIC_TEXT_LEN, Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)OLD_PASS_STATICTEXT, NULL, NULL
			);

			newPass_staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("Enter new password: "),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 2 * Y_STEP, X_STATIC_TEXT_LEN, Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)NEW_PASS_STATICTEXT, NULL, NULL
			);
			newPass2_staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("Repeat new password"),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 3 * Y_STEP, X_STATIC_TEXT_LEN, Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)NEW2_PASS_STATICTEXT, NULL, NULL
			);

			/******** Dynamic input ********/
			oldPass_input = CreateWindow(
				TEXT("EDIT"),
				TEXT(""),
				WS_BORDER | WS_CHILD | WS_VISIBLE | ES_PASSWORD,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + Y_STEP, X_INPUT_TEXT_LEN, Y_INPUT_TEXT_LEN,
				hDlg, (HMENU)OLD_PASS_INPUT, NULL, NULL
			);

			newPass_input = CreateWindow(
				TEXT("EDIT"),
				TEXT(""),
				WS_BORDER | WS_CHILD | WS_VISIBLE | ES_PASSWORD,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 2 * Y_STEP, X_INPUT_TEXT_LEN, Y_INPUT_TEXT_LEN,
				hDlg, (HMENU)NEW_PASS_INPUT, NULL, NULL
			);
			newPass2_input = CreateWindow(
				TEXT("EDIT"),
				TEXT(""),
				WS_BORDER | WS_CHILD | WS_VISIBLE | ES_PASSWORD,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 3 * Y_STEP, X_INPUT_TEXT_LEN, Y_INPUT_TEXT_LEN,
				hDlg, (HMENU)NEW2_PASS_INPUT, NULL, NULL
			);

			/******** Buttons ********/
			ok_button = CreateWindow(
				TEXT("BUTTON"),
				TEXT("OK"),
				WS_BORDER | WS_CHILD | WS_VISIBLE,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 4 * Y_STEP, X_BUTTON_SIZE, Y_BUTTON_SIZE,
				hDlg, (HMENU)IDOK, NULL, NULL
			);

			cancel_button = CreateWindow(
				TEXT("BUTTON"),
				TEXT("Cancel"),
				WS_BORDER | WS_CHILD | WS_VISIBLE,
				100 + BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 4 * Y_STEP, X_BUTTON_SIZE, Y_BUTTON_SIZE,
				hDlg, (HMENU)IDCANCEL, NULL, NULL
			);
#pragma endregion 
			break;
		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDCANCEL:
				{
					zeroize();
					DestroyWindow(hDlg);
					return TRUE;
				}
				case IDOK:
				{
					GetDlgItemTextA(hDlg, OLD_PASS_INPUT, (LPSTR)&pass_old, CCHMAX);
					GetDlgItemTextA(hDlg, NEW_PASS_INPUT, (LPSTR)&pass_new, CCHMAX);
					GetDlgItemTextA(hDlg, NEW2_PASS_INPUT, (LPSTR)&pass_new2, CCHMAX);

					pass_old[CCHMAX - 1] = 0;
					pass_new[CCHMAX - 1] = 0;
					pass_new2[CCHMAX - 1] = 0;

					if (0 == pass_new[0] || 0 == pass_new2[0] || 0 == pass_old[0]) {
						MessageBox(hDlg, TEXT("Fill everything!!!"), TEXT("Something missing"), 0);
					}
					else if (strncmp(pass_new, pass_new2, CCHMAX)) {
						MessageBox(hDlg, TEXT("Parheps your passwords don't match!!!"), TEXT("Something went realy wrong"), 0);
					}
					else {
#ifdef DEBUG
						MessageBox(hDlg, TEXT("Your passwords match!!!"), TEXT("Something went totaly well"), 0);
#endif
						DestroyWindow(hDlg);
						return TRUE;
					}
					return FALSE;
				}
			}
			break;
		case WM_CLOSE:
		{
			zeroize();
			DestroyWindow(hDlg);
			return TRUE;
		}
		case WM_DESTROY:
			PostQuitMessage(0);       /* send a WM_QUIT to the uMsg queue */
			return TRUE;
		default:                      /* for messages that we don't deal with */
			return DefWindowProc(hDlg, uMsg, wParam, lParam);
	}
	return FALSE;
}
LRESULT CALLBACK EnterPasswordProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_CREATE:
#pragma region WINDOW_CREATION
			/******** Static & input texts ********/
			staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("Enter your password:"),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN, X_STATIC_TEXT_LEN, Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)STATICTEXT, NULL, NULL
			);

			oldPass_input = CreateWindow(
				TEXT("EDIT"),
				TEXT(""),
				WS_BORDER | WS_CHILD | WS_VISIBLE | ES_PASSWORD,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN, X_INPUT_TEXT_LEN, Y_INPUT_TEXT_LEN,
				hDlg, (HMENU)OLD_PASS_INPUT, NULL, NULL
			);

			staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("It may be time to change your password.\nWould you like to?"),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, 120, X_STATIC_TEXT_LEN, 2 * Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)STATICTEXT, NULL, NULL
			);
			/******** Buttons ********/
			ok_button = CreateWindow(
				TEXT("BUTTON"),
				TEXT("OK"),
				WS_BORDER | WS_CHILD | WS_VISIBLE,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + Y_STEP, X_BUTTON_SIZE, Y_BUTTON_SIZE,
				hDlg, (HMENU)IDOK, NULL, NULL
			);

			cancel_button = CreateWindow(
				TEXT("BUTTON"),
				TEXT("Cancel"),
				WS_BORDER | WS_CHILD | WS_VISIBLE,
				100 + BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + Y_STEP, X_BUTTON_SIZE, Y_BUTTON_SIZE,
				hDlg, (HMENU)IDCANCEL, NULL, NULL
			);

			ok_button = CreateWindow(
				TEXT("BUTTON"),
				TEXT("Yes Sir!"),
				WS_BORDER | WS_CHILD | WS_VISIBLE,
				100 + BASE_FREME_INPUT_TEXT_LEN, 150, X_BUTTON_SIZE, Y_BUTTON_SIZE,
				hDlg, (HMENU)IDOK_CNGPASS, NULL, NULL
			);
#pragma endregion 
			break;
		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDCANCEL:
				{
					zeroize();
					DestroyWindow(hDlg);
					return TRUE;
				}
				case IDOK:
				{
					GetDlgItemTextA(hDlg, OLD_PASS_INPUT, (LPSTR)&pass_old, CCHMAX);
					pass_old[CCHMAX - 1] = 0;

					if (0 == pass_old[0]) {
						MessageBox(hDlg, TEXT("Fill everything!!!"), TEXT("Something missing"), 0);
					}
					else {
#ifdef DEBUG
						MessageBox(hDlg, TEXT("Your passwords match!!!"), TEXT("Something wen't totaly well"), 0);
#endif
						DestroyWindow(hDlg);
						return TRUE;
					}
					return FALSE;
				}
				case IDOK_CNGPASS:
				{
					gui_updatePassword();
					DestroyWindow(hDlg);
				}
			}
			break;
		case WM_CLOSE:
		{
			zeroize();
			DestroyWindow(hDlg);
			return TRUE;
		}
		case WM_DESTROY:
			PostQuitMessage(0);       /* send a WM_QUIT to the uMsg queue */
			return TRUE;
		default:                      /* for messages that we don't deal with */
			return DefWindowProc(hDlg, uMsg, wParam, lParam);
	}
	return FALSE;
}
LRESULT CALLBACK EnterNewPasswordProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_CREATE:
#pragma region WINDOW_CREATION
			/******** Static texts ********/
			staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("Choose a password wisely"),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN, X_STATIC_TEXT_LEN, Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)STATICTEXT, NULL, NULL
			);

			newPass_staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("Enter new password: "),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 1 * Y_STEP, X_STATIC_TEXT_LEN, Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)NEW_PASS_STATICTEXT, NULL, NULL
			);
			newPass2_staticText = CreateWindow(
				TEXT("STATIC"),
				TEXT("Repeat new password"),
				WS_CHILD | WS_VISIBLE,
				BASE_FREME_STATIC_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 2 * Y_STEP, X_STATIC_TEXT_LEN, Y_STATIC_TEXT_LEN,
				hDlg, (HMENU)NEW2_PASS_STATICTEXT, NULL, NULL
			);

			/******** Dynamic input ********/
			newPass_input = CreateWindow(
				TEXT("EDIT"),
				TEXT(""),
				WS_BORDER | WS_CHILD | WS_VISIBLE | ES_PASSWORD,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 1 * Y_STEP, X_INPUT_TEXT_LEN, Y_INPUT_TEXT_LEN,
				hDlg, (HMENU)NEW_PASS_INPUT, NULL, NULL
			);
			newPass2_input = CreateWindow(
				TEXT("EDIT"),
				TEXT(""),
				WS_BORDER | WS_CHILD | WS_VISIBLE | ES_PASSWORD,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 2 * Y_STEP, X_INPUT_TEXT_LEN, Y_INPUT_TEXT_LEN,
				hDlg, (HMENU)NEW2_PASS_INPUT, NULL, NULL
			);

			/******** Buttons ********/
			ok_button = CreateWindow(
				TEXT("BUTTON"),
				TEXT("OK"),
				WS_BORDER | WS_CHILD | WS_VISIBLE,
				BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 4 * Y_STEP, X_BUTTON_SIZE, Y_BUTTON_SIZE,
				hDlg, (HMENU)IDOK, NULL, NULL
			);

			cancel_button = CreateWindow(
				TEXT("BUTTON"),
				TEXT("Cancel"),
				WS_BORDER | WS_CHILD | WS_VISIBLE,
				100 + BASE_FREME_INPUT_TEXT_LEN, BASE_FREME_STATIC_TEXT_LEN + 4 * Y_STEP, X_BUTTON_SIZE, Y_BUTTON_SIZE,
				hDlg, (HMENU)IDCANCEL, NULL, NULL
			);
#pragma endregion 
			break;
		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDCANCEL:
				{
					DestroyWindow(hDlg);
					return TRUE;
				}
				case IDOK:
				{
					GetDlgItemTextA(hDlg, NEW_PASS_INPUT, (LPSTR)&pass_new, CCHMAX);
					GetDlgItemTextA(hDlg, NEW2_PASS_INPUT, (LPSTR)&pass_new2, CCHMAX);
					pass_new[CCHMAX - 1] = 0;
					pass_new2[CCHMAX - 1] = 0;

					if (0 == pass_new[0] || 0 == pass_new2[0]) {
						MessageBox(hDlg, TEXT("Fill everything!!!"), TEXT("Something missing"), 0);
					}
					else if (strncmp(pass_new, pass_new2, CCHMAX)) {
						MessageBox(hDlg, TEXT("Parheps your passwords don't match!!!"), TEXT("Something wen't realy wrong"), 0);
					}
					else {
						DestroyWindow(hDlg);
						return TRUE;
					}
					return FALSE;
				}
			}
			break;
		case WM_CLOSE:
		{
			DestroyWindow(hDlg);
			return TRUE;
		}
		case WM_DESTROY:
			PostQuitMessage(0);
			return TRUE;
		default:
			return DefWindowProc(hDlg, uMsg, wParam, lParam);
	}
	return FALSE;
}

void gui_createPassword(char *& newPass) {
	TCHAR szClassName[] = _T("CreatePasswordWindowsApp");
	HINSTANCE hThisInstance = GetModuleHandle(nullptr);
	BOOL ret;
	MSG msg;											/* Here messages to the application are saved */
	WNDCLASSEX wincl;									/* Data structure for the windowclass */

	wincl.hInstance = hThisInstance;
	wincl.lpszClassName = szClassName;
	wincl.lpfnWndProc = EnterNewPasswordProc;			/* This function is called by windows */
	wincl.style = CS_DBLCLKS;							/* Catch double-clicks */
	wincl.cbSize = sizeof(WNDCLASSEX);

	wincl.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
	wincl.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
	wincl.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wincl.lpszMenuName = nullptr;						/* No menu */
	wincl.cbClsExtra = 0;								/* No extra bytes after the window class */
	wincl.cbWndExtra = 0;								/* structure or the window instance */
	wincl.hbrBackground = (HBRUSH)COLOR_WINDOW;

	RegisterClassEx(&wincl);

	/* The class is registered, let's create the program*/
	const HWND create_password = CreateWindowEx(
		0,												/* Extended possibilites for variation */
		szClassName,									/* Classname */
		TEXT("NoteHack++   |   Create - Password"),     /* Title Text */
		WS_OVERLAPPED | WS_MINIMIZEBOX | WS_SYSMENU,	/* default window */
		CW_USEDEFAULT,									/* Windows decides the position */
		CW_USEDEFAULT,									/* where the window ends up on the screen */
		WINDOW_WIDTH,									/* The programs width */
		WINDOW_HEIGHT,									/* and height in pixels */
		HWND_DESKTOP,									/* The window is a child-window to desktop */
		nullptr,										/* No menu */
		hThisInstance,									/* Program Instance handler */
		nullptr											/* No Window Creation data */
	);
	ShowWindow(create_password, SW_SHOW);

	while ((ret = GetMessage(&msg, nullptr, 0, 0)) != 0) {
		if (ret == -1)
			return;
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	int len;
	if (0 != pass_new[0]) {
		len = strlen(pass_new);
		if (newPass) {
			delete[] newPass;
			newPass = nullptr;
		}
		newPass = new char[len + 1];
		for (int i = 0; i <= len; ++i)
			newPass[i] = pass_new[i];
	}
	zeroize();
	return;
}
void gui_enterPassword(char *& newPass, char *& oldPass) {
	TCHAR szClassName[] = _T("EnterPasswordWindowsApp");
	HINSTANCE hThisInstance = GetModuleHandle(nullptr);
	BOOL ret;
	MSG msg;								            /* Here messages to the application are saved */
	WNDCLASSEX wincl;									/* Data structure for the windowclass */

	wincl.hInstance = hThisInstance;
	wincl.lpszClassName = szClassName;
	wincl.lpfnWndProc = EnterPasswordProc;				/* This function is called by windows */
	wincl.style = CS_DBLCLKS;							/* Catch double-clicks */
	wincl.cbSize = sizeof(WNDCLASSEX);

	wincl.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
	wincl.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
	wincl.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wincl.lpszMenuName = nullptr;						/* No menu */
	wincl.cbClsExtra = 0;								/* No extra bytes after the window class */
	wincl.cbWndExtra = 0;								/* structure or the window instance */
														/* Use Windows's default colour as the background of the window */
	wincl.hbrBackground = (HBRUSH)COLOR_WINDOW;

	RegisterClassEx(&wincl);

	HWND create_password = CreateWindowEx(
		0,												/* Extended possibilites for variation */
		szClassName,									/* Classname */
		TEXT("NoteHack++   |   Enter Password"),        /* Title Text */
		WS_OVERLAPPED | WS_MINIMIZEBOX | WS_SYSMENU,    /* default window */
		CW_USEDEFAULT,									/* Windows decides the position */
		CW_USEDEFAULT,									/* where the window ends up on the screen */
		WINDOW_WIDTH,									/* The programs width */
		WINDOW_HEIGHT,									/* and height in pixels */
		HWND_DESKTOP,									/* The window is a child-window to desktop */
		nullptr,										/* No menu */
		hThisInstance,									/* Program Instance handler */
		nullptr											/* No Window Creation data */
	);
	ShowWindow(create_password, SW_SHOW);

	while (ret = GetMessage(&msg, nullptr, 0, 0)) {
		if (ret == -1)
			return;
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	int len;
	if (0 != pass_new[0]) {
		len = strlen(pass_new);
		if (newPass) {
			delete[] newPass;
			newPass = nullptr;
		}
		newPass = new char[len + 1];
		for (int i = 0; i <= len; ++i)
			newPass[i] = pass_new[i];
	}
	if (0 != pass_old[0]) {
		len = strlen(pass_old);
		if (oldPass) {
			delete[] oldPass;
			oldPass = nullptr;
		}
		oldPass = new char[len + 1];
		for (int i = 0; i <= len; ++i)
			oldPass[i] = pass_old[i];
	}
	zeroize();
}
void gui_updatePassword() {
	TCHAR szClassName[] = _T("ChangePasswordWindowsApp");
	HINSTANCE hThisInstance = GetModuleHandle(nullptr);
	BOOL ret;
	MSG msg;											/* Here messages to the application are saved */
	WNDCLASSEX wincl;									/* Data structure for the windowclass */

	wincl.hInstance = hThisInstance;
	wincl.lpszClassName = szClassName;
	wincl.lpfnWndProc = EnterUpdatePasswordProc;		/* This function is called by windows */
	wincl.style = CS_DBLCLKS;							/* Catch double-clicks */
	wincl.cbSize = sizeof(WNDCLASSEX);

	wincl.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
	wincl.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
	wincl.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wincl.lpszMenuName = nullptr;						/* No menu */
	wincl.cbClsExtra = 0;								/* No extra bytes after the window class */
	wincl.cbWndExtra = 0;								/* structure or the window instance */
														/* Use Windows's default colour as the background of the window */
	wincl.hbrBackground = (HBRUSH)COLOR_WINDOW;

	RegisterClassEx(&wincl);

	/* The class is registered, let's create the program*/
	HWND change_password = CreateWindowEx(
		0,												/* Extended possibilites for variation */
		szClassName,									/* Classname */
		TEXT("NoteHack++   |   Change - Password"),
		WS_OVERLAPPED | WS_MINIMIZEBOX | WS_SYSMENU,	/* default window */
		CW_USEDEFAULT,									/* Windows decides the position */
		CW_USEDEFAULT,									/* where the window ends up on the screen */
		WINDOW_WIDTH,									/* The programs width */
		WINDOW_HEIGHT,									/* and height in pixels */
		HWND_DESKTOP,									/* The window is a child-window to desktop */
		nullptr,										/* No menu */
		hThisInstance,									/* Program Instance handler */
		nullptr											/* No Window Creation data */
	);
	ShowWindow(change_password, SW_SHOW);

	while (ret = GetMessage(&msg, nullptr, 0, 0)) {
		if (ret == -1)
			return;
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

inline void zeroize() {
	memset(pass_new, 0, CCHMAX);
	memset(pass_new2, 0, CCHMAX);
	memset(pass_old, 0, CCHMAX);
}
