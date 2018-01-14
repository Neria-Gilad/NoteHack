#pragma once
//******************************************************************//
//					includes & macros
//******************************************************************//
#include "stdafx.h"
#include "CryptoOperations.h"
#include "gui.h"
#include <fstream>
#include <string>
#include <wincrypt.h>
#ifndef MACRO16
#define MACRO16 16
#endif
#ifndef MACRO32
#define MACRO32 32
#endif
#ifndef MACRO64
#define MACRO64 64
#endif

//******************************************************************//
//					declerations
//******************************************************************//
/**
 * \brief defines a user. has rsa keys and salt, iv information.
 */
struct profileEntry;

/**
 * \brief defines a file. information required to find and decrypt
 */
struct keyEntry;

static bool _____dont_delete______;//for finding dll path
char* derivedKey = nullptr;
char* KSFPath = nullptr;

/**
 * \brief finds the location of the dll file and updates the expected location of the ksf file appropriately.
 */
void updateKSFPath();
profileEntry* initAsymmetric();//create rsa key pair and return a profileEntry (private key is encrypted)
bool createEntryFile(char* path);// make new key storage file with new private and public keys
bool changePassword(char* path, char* oldKey, char* newKey);
keyEntry* findEntry(char* path, char* id, char* tag); //in key storage file, find correct entry and return struct
bool updateEntry(char* path, const keyEntry* old, char* tag); //update struct in key storage file
/**
 * \brief appends a keyEntry to the ksf file
 * \param path path of the ksf
 * \param entry what to append
 * \return true if there were no problems
 */
bool addEntry(char* path, keyEntry* entry);
char* entryToPT(keyEntry * entry, CryptoScheme* scheme, char* derivedKey, char* cipher, unsigned __int64 len); //decrypt all relevant keys and return file plainText
char* createEntryAndCipher(CryptoScheme* scheme, char* derivedKey, char* text, unsigned __int64 len); //encrypt text, return it and create entry in main file.
bool checkPassword(char * key, profileEntry* profile);//quick decrypt of profile to look for "GOOD" string
/**
 * \brief  prompts the user to enter a password and updates global derived password
 * \return true if successful
 */
bool getPasswordFromUser();


//******************************************************************//
//					implementations
//******************************************************************//

struct profileEntry
{
	unsigned char salt[MACRO16]; // for kdf
	unsigned char iv[MACRO16]; //for ctr
	char encryptedKey[sizeof(RSA_private)]; //encrypted using ctr
	RSA_public pub;//encrypt file keys
};

struct keyEntry
{
	char id[MACRO16]; //file id
	char encryptedKey[RSA_BYTES];//when decrypted, can unlock the file
	char tag[MACRO16]; //tag for gcm error checking
};

void updateKSFPath()
{
	char* path = new char[MAX_PATH];
	HMODULE hm = nullptr;
	//get handle to get file location
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)&_____dont_delete______, &hm))
	{
		MessageBoxA(0, "problem finding dll", 0, 0);
	}
	GetModuleFileNameA(hm, path, MAX_PATH);//gets full path, with file name
	int pathSize = strlen(path);
	path[pathSize - 3] = 'k'; //
	path[pathSize - 2] = 's'; //|| same path and name, with "ksf" replacing "dll"
	path[pathSize - 1] = 'f'; //
	KSFPath = path;
	path = nullptr;
}

bool KSFExists()
{
	updateKSFPath();
	std::fstream temp(KSFPath);
	bool flag = temp ? true : false; //temp can't be converted to bool directly
	temp.close();
	return flag;
}

profileEntry* initAsymmetric()//create rsa key pair and return a profileEntry (private key is encrypted)
{
	profileEntry * ret = new profileEntry;
	RSA_private tempPriv;
	if (rsa_init(&(ret->pub), &tempPriv))
	{
		MessageBoxA(0, "problem creating key Pair", 0, 0);
		return nullptr; //failed
	}
	char* encryptedKey = (char*)encrypt_aes256_ctr(ret->iv, (unsigned char*)derivedKey, (char*)&tempPriv, sizeof(RSA_private)); //will initialize iv
	if (!encryptedKey)
	{
		MessageBoxA(0, "problem encrypting", 0, 0);
		return nullptr; //failed
	}
	memcpy(ret->encryptedKey, encryptedKey, sizeof(RSA_private));

	if (encryptedKey)//always true but just in case...
	{
		delete[] encryptedKey;
		encryptedKey = nullptr;
	}
	return ret;
}

bool createEntryFile(char* path)// make new key storage file with new private and public keys
{
	char * password = 0;
	gui_createPassword(password);
	if (!password)//user clicked on cancel
		return false;

	unsigned char salt[MACRO16] = { 0 };
	derivedKey = (char*)derive_key_pbkdf2((unsigned char*)password, strlen(password), salt, true);//get crypto key from password & generate new salt for it
	if (password)
	{
		delete[] password;
		password = nullptr;
	}
	if (!salt[0] && !salt[1]) MessageBoxA(0, "problem deriving key", 0, 0);

	std::ofstream f;
	f.open(path, std::ios::binary | std::ios::out);
	if (!f) return false;

	profileEntry* initEntry = initAsymmetric();
	memcpy(initEntry->salt, salt, MACRO16);

	f.write((char*)initEntry, sizeof(profileEntry));//binary write
	f.close();
	return true;
}

bool changePassword(char* path, char* oldKey, char* newKey)//oldKey and newKey are already derived
{
	profileEntry profile;
	std::fstream f(path, std::ios::binary | std::ios::out | std::ios::in);
	if (!f) return false;
	f.read((char*)&profile, sizeof(profileEntry));//binary read
	char * priv = (char*)decrypt_aes256_ctr(profile.iv, (unsigned char*)oldKey, (char*)profile.encryptedKey, sizeof(RSA_private));
	if (!priv) return false;
	char * newEncPriv = (char*)encrypt_aes256_ctr(profile.iv, (unsigned char*)newKey, (char*)priv, sizeof(RSA_private));
	if (!newEncPriv) return false;
	memcpy(profile.encryptedKey, newEncPriv, sizeof(RSA_private));

	if (priv)
	{
		delete[] priv;
		priv = nullptr;
	}
	if (newEncPriv)
	{
		delete[] newEncPriv;
		newEncPriv = nullptr;
	}
	f.seekp(0, std::ios_base::beg);//to overwrite profile
	f.write((char*)&profile, sizeof(profileEntry));//binary write
	f.close();
	return true;
}

bool addEntry(char* path, keyEntry* entry)
{
	std::fstream entryFile(path, std::ios::binary | std::ios::out | std::ios::in);
	if (!entryFile) { return false; }
	try {
		entryFile.seekp(0, std::ios::end);
		entryFile.write((char*)entry, sizeof(keyEntry));
		entryFile.close();
		return true;
	}
	catch (...)
	{
		entryFile.close();
		return false;
	}
}

keyEntry* findEntry(char* path, char* id, char* tag) //in key storage file, find correct entry and return struct
{
	keyEntry* ret = new keyEntry;
	std::ifstream entryFile(path, std::ios::binary | std::ios::in);
	try
	{
		entryFile.seekg(sizeof(profileEntry));//skip profile, go directly to keys
		while (!entryFile.eof())
		{
			bool flag = true;
			entryFile.read((char*)ret, sizeof(keyEntry));
			//is this the file we're looking for?
				if(memcmp(ret->id,id,MACRO16)||memcmp(ret->tag,tag,MACRO16))
					flag = false; //no
			if (flag)
			{//yes!
				entryFile.close();
				return ret;
			} 
		}
	}
	catch (...)
	{
		MessageBoxA(0, "problem searching", 0, 0);
		entryFile.close();
		return nullptr;
	}
	entryFile.close();
	return nullptr;
}

profileEntry* getProfile(char* path)
{
	std::ifstream entryFile(path, std::ios::binary | std::ios::in);
	if (!entryFile) return nullptr;
	profileEntry* ret = new profileEntry;
	try
	{
		entryFile.read((char*)ret, sizeof(profileEntry));
	}
	catch (...)
	{
		MessageBoxA(0, "failed to get profile", 0, 0);
		if (ret)
		{
			delete ret;
			ret = nullptr;
		}
		entryFile.close();
		return nullptr;
	}
	entryFile.close();
	return ret;
}

bool updateEntry(char* path, const keyEntry* old, char* tag) //update struct in key storage file
{
	keyEntry check;
	std::fstream entryFile(path, std::ios::binary | std::ios::out | std::ios::in);
	if (!entryFile) return false;
	entryFile.seekg(sizeof(profileEntry));//skip profile, go directly to keys
	try
	{
		while (!entryFile.eof())
		{
			bool flag = true;
			entryFile.read((char*)&check, sizeof(keyEntry));
			for (int i = 0; i < MACRO16; i++)//is this the file we're looking for?
				if (check.id[i] != old->id[i] || check.tag[i] != old->tag[i])
				{
					flag = false;//no
					break;
				}
			if (flag)//yes!
			{
				entryFile.seekp((unsigned _int64)entryFile.tellg() - sizeof(keyEntry)); //in case write pointer is not the same as the read
				for (int i = 0; i < MACRO16; i++) //only tag should change due to file edit
					check.tag[i] = tag[i];
				entryFile.write((char*)&check, sizeof(keyEntry));
				entryFile.close();
				return true;
			}
		}
	}
	catch (...)
	{
		entryFile.close();
		return false;
	}
	entryFile.close();
	return false;
}

keyEntry* createNewEntry(RSA_public* rsaPubKey) //creates a new keyEntery with a new (random and encrypted) key
{
	keyEntry* ret = new keyEntry;
	if (init_file_key(ret->encryptedKey, rsaPubKey)) {
		MessageBoxA(0, "init invalid", 0, 0);
		return nullptr;
	}
	return ret;
}

char* entryToPT(keyEntry * entry, CryptoScheme* scheme, char* derivedKey, char* cipher, unsigned __int64 len) //decrypt all relevant keys and return file plainText
{//it is assumed there is already a KSF file
	profileEntry* profile = getProfile(KSFPath);
	if (!profile) return nullptr;
	RSA_private* rsaKey = (RSA_private*)decrypt_aes256_ctr(profile->iv, (unsigned char*)derivedKey, profile->encryptedKey, sizeof(RSA_private));
	if (!rsaKey) return nullptr;
	unsigned char* fileKey = decrypt_rsa_pkcs15(&(profile->pub), rsaKey, entry->encryptedKey, 3 * MACRO32);
	if (!fileKey) return nullptr;
	return (char*)decrypt_gcm256_authenticate(scheme, fileKey, cipher, len);
}

char* createEntryAndCipher(CryptoScheme* scheme, char* derivedKey, char* text, unsigned __int64 len) //encrypt text, return it and create entry in main file.
{//it is assumed there is already a KSF file
	profileEntry* profile = getProfile(KSFPath);

	if (!profile) return nullptr;
	keyEntry* entry = findEntry(KSFPath, (char*)scheme->flid, (char*)scheme->tag);
	if (!entry)//no existing entry
	{
		entry = createNewEntry(&(profile->pub));
		memcpy(entry->id, scheme->flid, MACRO16);
	}

	RSA_private* rsaKey = (RSA_private*)decrypt_aes256_ctr(profile->iv, (unsigned char*)derivedKey, profile->encryptedKey, sizeof(RSA_private));
	if (!rsaKey) return nullptr;
	unsigned char* fileKey = decrypt_rsa_pkcs15(&(profile->pub), rsaKey, entry->encryptedKey, 3 * MACRO32);
	if (!fileKey) return nullptr;
	char* cipher = (char*)encrypt_gcm256(scheme, fileKey, text, len);
	if (!cipher) return nullptr;
	memcpy(entry->tag, scheme->tag, MACRO16);//the encryption created the tag in scheme

	if (!updateEntry(KSFPath, entry, (char*)scheme->tag)) //couldn't update. since finding profile worked, its because the entry doesnt exist
		addEntry(KSFPath, entry);//so add it as new. if someone messed with the file during saving, he deserves for his ksf file to fill up unnecessarily. or crash
	return cipher;
}

bool checkPassword(char * key, profileEntry* profile)//quick decrypt of profile to look for "GOOD" string
{
	bool isGood = true; //was false before for lopp was existed
	RSA_private* priv = (RSA_private*)decrypt_aes256_ctr(profile->iv, (unsigned char*)key, profile->encryptedKey, sizeof(RSA_private));
	char good[] = "GOOD";
	for (int i = 0; i < 5; i++)
		if (priv->good[i] != good[i]) {
			isGood = false;
			break;
		}
	if (priv)
	{
		delete[](char*)priv;
		priv = nullptr;
	}
	return isGood;
}

bool getPasswordFromUser()
{
	profileEntry* profile = getProfile(KSFPath);
	char * password = nullptr;
	char * newPassword = nullptr;

	while (true)//only simple way to avoid redundant code
	{
		gui_enterPassword(newPassword, password);
		if (!password)//user clicked on cancel
			return false;
		derivedKey = (char*)derive_key_pbkdf2((unsigned char*)password, strlen(password), profile->salt, false);//get crypto key from password
		if (!derivedKey) return false;
		if (checkPassword(derivedKey, profile)) //will be true if password is correct
			break;
		MessageBoxA(0, "incorrect password. try again", 0, 0); //if checkPassword didn't cause break
	}
	if (newPassword)//meaning the user changed his password
	{
		char* tempKey = (char*)derive_key_pbkdf2((unsigned char*)newPassword, strlen(newPassword), profile->salt, false);//get crypto key from password
		if (!tempKey) return false;
		if (changePassword(KSFPath, derivedKey, tempKey))
		{
			if (derivedKey)//just in case. probably always true
				delete[] derivedKey;
			derivedKey = tempKey;
			tempKey = nullptr;
		}
	}

	if (password)
	{
		delete[] password;
		password = nullptr;
	}
	if (newPassword)
	{
		delete[] newPassword;
		newPassword = nullptr;
	}
	if (profile)
	{
		delete profile;
		profile = nullptr;
	}
	return true;
}