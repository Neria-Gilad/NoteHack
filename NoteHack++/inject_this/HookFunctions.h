#pragma once
//******************************************************************//
//					includes & macros
//******************************************************************//
#include "CryptoScheme.h"
#include "CryptoOperations.h"
#include "KeyStorageFileOperations.h"
#include <CommCtrl.h>
#ifndef SCM_LENGTH
#define SCM_LENGTH 89
#endif
#define generic_fopen _wfopen	//match notepad++ vv
#pragma warning(disable:4996)	//for file open, to match notepad++. only one use of such a horror

//******************************************************************//
//					declerations
//******************************************************************//
CryptoScheme* newCurrentScheme;
unsigned __int64 fileSize = 0;
unsigned int read = 0;
char* PText;
TCHAR * filename;
char* savedText;
DWORD jmpBackAddyLoad;
DWORD jmpBackAddyNewLoad;
DWORD jmpBackAddyNewSave;
DWORD jmpBackAddyNewAfterSave;


bool Hook(void * toHook, void * ourFunct, int len);
size_t loadBlock(char * data, size_t size, size_t nmemb, FILE * fpointer);
/**
 * \brief if something went wrong with the encryption. just saves plaintext to avoid data loss
 * \param buf the plaintext
 * \param lengthDoc length of plaintext
 * \return
 */
char* FailedBuferReplace(char* buf, unsigned int const lengthDoc);
char* ReplaceBuffer(char* buf, unsigned int const lengthDoc);
void deleteBuffer();
void __declspec() overLoad();
void __declspec() newOverLoad();
void __declspec() newAfterSave();
void __declspec() newOverSave();
DWORD WINAPI MainThread(LPVOID param);



//******************************************************************//
//					implementations
//******************************************************************//
bool Hook(void * toHook, void * ourFunct, int len) {//actual hooking is done here
	if (len < 5) { //cannot replace jmp
		return false;
	}

	DWORD curProtection;
	VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);//allow changing .text

	memset(toHook, 0x90, len); //for cleanliness, fill with nops

	const DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;//distance between hook and desired jump. eip will be +5 (sizeof(jmp)==5 bytes)

	*(BYTE*)toHook = 0xE9; //jmp
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;

	DWORD temp;//give it something...
	VirtualProtect(toHook, len, curProtection, &temp);//restore old protection

	return true;
}


void toBuffer(size_t &numToRead, char data[], unsigned __int64 totalSize)//memcpy with checks
{
	for (unsigned int i = 0; i < numToRead; ++i)
	{
		data[i] = PText[read++];
		if (read >= totalSize) //read last byte. only == is needed, >= just in case
		{
			numToRead = i + 1;
			break;
		}
	}
}

size_t loadBlock(char * data, size_t size, size_t numToRead, FILE * fpointer)//replaces fread function in notepad++. makes believe it works the same way
{
	if (!PText) { //first iteration

		FILE *fp = generic_fopen(filename, TEXT("rb"));

		_fseeki64(fp, 0, SEEK_END);
		fileSize = _ftelli64(fp);
		rewind(fp);
		if (fileSize >= SCM_LENGTH)//maybe an encrypted file
		{
			if (!KSFExists())//also updates KSFPath;
			{
				if (!createEntryFile(KSFPath))
				{
					MessageBoxA(0, "could not create KSF file...\nplease try closing the tab and loading the file again", 0, 0);
					fclose(fp);
					return 0;
				}
			}

			char schemeBuffer[SCM_LENGTH + 1];
			if (fread(schemeBuffer, 1, SCM_LENGTH, fp) != SCM_LENGTH)
				MessageBoxA(0, "problem reading scheme", 0, 0);

			if (newCurrentScheme)
			{
				delete newCurrentScheme;
				newCurrentScheme = nullptr;
			}
			newCurrentScheme = CryptoScheme::fromFile(schemeBuffer);

			fileSize -= SCM_LENGTH;//because the rest must be read as if it is everything
			if (newCurrentScheme) //scheme is valid
			{
				keyEntry *tmp = findEntry(KSFPath, (char*)newCurrentScheme->flid, (char*)newCurrentScheme->tag);

				if (tmp)//file info is indeed in KSF
				{
					if (!derivedKey)
						getPasswordFromUser();//update globally saved key
					if (!derivedKey)//getPassword should have initialized it...
					{
						MessageBoxA(0, "problem with password, loading nothing.\nsaving now will cause data loss", 0, 0);
						delete tmp;
						fclose(fp);
						return 0;//tell notepad++ that nothing was loaded
					}
					char* cipherText = new char[fileSize];
					fread(cipherText, 1, fileSize, fp);

					PText = entryToPT(tmp, newCurrentScheme, derivedKey, cipherText, fileSize);
					if (!PText)//entryToPT should have initialized it
					{
						MessageBoxA(0, "problem decrypting, loading nothing.\nsaving now will cause data loss", 0, 0);
						read = 0;
						delete[] PText;
						PText = nullptr;
						return 0;//tell notepad++ that nothing was loaded
					}
					fclose(fp);
					if (cipherText) delete[] cipherText;
				}
				else //file has been encrypted by another's NoteHack++, load as plaintext
				{
					fileSize += SCM_LENGTH;
					rewind(fp);//undo scheme read
					PText = new char[fileSize];
					fread(PText, 1, fileSize, fp);
				}
			}
			else //file doesn't have a valid scheme, load as plaintext
			{
				fileSize += SCM_LENGTH;
				rewind(fp);//undo scheme read
				PText = new char[fileSize];
				fread(PText, 1, fileSize, fp);
			}
		}
		else {//could not have been encrypted by us, load plain.
			PText = new char[fileSize];
			fread(PText, 1, fileSize, fp);
		}
	}

	if (read >= fileSize)
	{
		read = 0; //for next read
		if (PText) {
			delete[] PText;
			PText = nullptr;
		}
		return 0;//nothing was read
	}

	toBuffer(numToRead, data, fileSize);//basically memcpy with some checks

	if (PText && !numToRead) //!numToRead means notepad wants to read nothing, so we give it nothing.
	{
		delete[] PText;
		PText = nullptr;
		read = 0;
	}//in case of a problem

	return numToRead;
}

char* FailedBuferReplace(char* buf, unsigned int const lengthDoc)
{
	MessageBoxA(0, "problem with password. saving without encryption, sorry...", 0, 0);
	savedText = new char[SCM_LENGTH + lengthDoc];
	memcpy(savedText, buf, lengthDoc);
	memset(savedText + lengthDoc, 0x20, SCM_LENGTH);//fill with spaces.. otherwise too many changes for whats technically an exception
	return savedText;
}

char* ReplaceBuffer(char* buf, unsigned int const lengthDoc)//this is what the args are called in the original notepad++ function
{
	//before anything, make sure ksf is in order
	if (!KSFExists())//also updates KSFPath
		createEntryFile(KSFPath);//will ask for password as well
	else if (!derivedKey)//KSF exists, but user has not entered a password yet
		if (!getPasswordFromUser())
			return FailedBuferReplace(buf, lengthDoc);

	FILE *fp = generic_fopen(filename, TEXT("rb"));
	_fseeki64(fp, 0, SEEK_END);
	_int64 fileLen = _ftelli64(fp);
	rewind(fp);
	if (fileLen >= SCM_LENGTH) 
	{
		if (newCurrentScheme)//we need to reload scheme - required for tab support
		{
			delete newCurrentScheme;
			newCurrentScheme = nullptr;
		}
		char schemeBuffer[SCM_LENGTH + 1];
		if (fread(schemeBuffer, 1, SCM_LENGTH, fp) != SCM_LENGTH)//we checked file length so there must be sum ting wong (wi tu lo?)
			MessageBoxA(0, "problem reading scheme", 0, 0);
		newCurrentScheme = CryptoScheme::fromFile(schemeBuffer);//returns null if not valid scheme
		if (!newCurrentScheme) newCurrentScheme = new CryptoScheme; //new file or ruined scheme. either way, a new one is necessary
	}
	else //file too short to have scheme in it
	{
		if (newCurrentScheme)
		{
			delete newCurrentScheme;
			newCurrentScheme = nullptr;
		}
		newCurrentScheme = new CryptoScheme;//no scheme so make new one
	}
	fclose(fp);


	char* tempCipher = createEntryAndCipher(newCurrentScheme, derivedKey, buf, lengthDoc);//returns ecrypted, same length. updates scheme as well
	if (!tempCipher)
		return FailedBuferReplace(buf, lengthDoc);
	char* tempScheme = CryptoScheme::toFile(newCurrentScheme);//turn the scheme into text format
	savedText = new char[SCM_LENGTH + lengthDoc];
	memcpy(savedText, tempScheme, SCM_LENGTH);//copy scheme
	memcpy(savedText + SCM_LENGTH, tempCipher, lengthDoc);//copy rest

	return savedText;
}

void deleteBuffer()//tie up loose ends
{
	//we dont delete buf because notepad++ uses it to show the text.
	//we created savedText so we decide how it dies (painfully)
	if (savedText)
	{
		delete[] savedText;
		savedText = nullptr;
	}
}


void __declspec(naked) overLoad() {//simplest way to find path of requested file
	__asm {
		lea eax, [ebp - 536] //path
		mov filename, eax //save globally
		jmp[jmpBackAddyLoad]
	}
}

void __declspec(naked) newOverLoad() {//replaced call in original asm, with same args, so no further changes needed
	__asm {
		call loadBlock
		jmp[jmpBackAddyNewLoad]
	}
}

void __declspec(naked) newOverSave() {//called function returns new pointer with encrypted buffer. in OG asm buffer is eax so return is good
	__asm {
		mov[ebp - 592], eax//replace overwritten asm
		push ebx //length of buffer
		push eax //char* buffer
		lea eax, [ebp - 536] //since eax is dead anyway, lets use it
		mov filename, eax //path of file to be saved <- this one line just added tab support! yay!
		call ReplaceBuffer//eax will change to ciphertext buffer muhaha
		add esp, 8
		add ebx, SCM_LENGTH//to accomodate the added scheme, undone in newAfterSave()
		jmp[jmpBackAddyNewSave]
	}
}

void __declspec(naked) newAfterSave() {//undo changes to buffer before notepad++ reloads it
	__asm {
		mov[ebp - 568], eax//overwritten asm
		call deleteBuffer //we made new, so delete now
		sub ebx, SCM_LENGTH	//shhhhhhhhh no one can know we added this
		jmp[jmpBackAddyNewAfterSave]
	}
}


DWORD WINAPI MainThread(LPVOID param) {
	const DWORD baseAddr = (DWORD)GetModuleHandle(nullptr);
	int hookLength;
	DWORD hookAddress;

	//override load
	hookLength = 6;
	////0x00421A76
	// 3A0000 + RelativeAddr = address in ida
	hookAddress = baseAddr + 0x81A76;
	jmpBackAddyLoad = hookAddress + hookLength;
	Hook((void*)hookAddress, overLoad, hookLength);

	//new load override
	hookLength = 5;
	////0x0041E4C2
	hookAddress = baseAddr + 0x1E4C2;
	jmpBackAddyNewLoad = hookAddress + hookLength;
	Hook((void*)hookAddress, newOverLoad, hookLength);

	//new save override
	hookLength = 6;
	////0x0041EF3D
	hookAddress = baseAddr + 0x1EF3D;
	jmpBackAddyNewSave = hookAddress + hookLength;
	Hook((void*)hookAddress, newOverSave, hookLength);

	//new after save override - to release created buffer
	hookLength = 6;
	////0x0041EF63
	hookAddress = baseAddr + 0x1EF63;
	jmpBackAddyNewAfterSave = hookAddress + hookLength;
	Hook((void*)hookAddress, newAfterSave, hookLength);


	//when a file is saved a second time, a messagebox pops up and ruins everything.
	//we need to get rid of it to avoid inconvenience and/or data loss
	//0x003FB4F5 is call messagebox.. just replace with mov eax,7 - B807000000 in bytes. 7 is ID_NO
	DWORD curProtection;
	hookAddress = baseAddr + 0x5B4E7;
	VirtualProtect((void*)hookAddress, 19, PAGE_EXECUTE_READWRITE, &curProtection);//allow changing .text
	memset((void*)hookAddress, 0x90, 14);//nops to get rid of all the pushes because messagebox func restores esp itself
	memset((void*)(hookAddress + 14), 0xB8, 1);	 ////|
	memset((void*)(hookAddress + 15), 0x07, 1);	 /////>replace call to messagebox with ID_NO (7)
	memset((void*)(hookAddress + 17), 0x00, 3);	 ////
	memset((void*)(hookAddress + 19), 0x90, 1);	 //

	DWORD temp;//give it something...
	VirtualProtect((void*)hookAddress, 19, curProtection, &temp);//restore old protection

	while (true) {
		if (GetAsyncKeyState(VK_ESCAPE)) break;
		Sleep(50);
	}

	FreeLibraryAndExitThread((HMODULE)param, 0);
}