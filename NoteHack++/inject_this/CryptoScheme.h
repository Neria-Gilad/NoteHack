#pragma once
//******************************************************************//
//					includes & macros
//******************************************************************//
#ifndef MACRO16
#define MACRO16 16
#endif
#ifndef MACRO32
#define MACRO32 32
#endif

#ifndef SIZEOF_IV 
#define SIZEOF_IV 16
#endif
#ifndef SIZEOF_SALT
#define SIZEOF_SALT 16
#endif
#ifndef SIZEOF_ID
#define SIZEOF_ID 16
#endif
#ifndef SIZEOF_TAG 
#define SIZEOF_TAG 16
#endif
#ifndef KDF_ITER_NUM
#define KDF_ITER_NUM 100000
#endif

/*
 * actually, we could use a struct. 
 */
//******************************************************************//
//					class
//******************************************************************//

class CryptoScheme {
public:
	//*********	Constructors *********//
	CryptoScheme(const char* algorithm, const char* mode, const char* iv, const char* salt, const char* mac);
	CryptoScheme();
	~CryptoScheme();

	//*********	Fields *********//
	char algorithm[MACRO16 + 1]{};			// algorithm used; like AES265
	char mode[MACRO16 + 1]{};				// mode used; like CBC
	unsigned char iv[SIZEOF_IV + 1]{};		// initialization vector, should be random
	unsigned char flid[SIZEOF_ID + 1]{};	// anti pre-computed SHA256(password); instead, we use SHA256(password+salt)
	unsigned char tag[SIZEOF_TAG + 1]{};	// authentication by GCM

	//*********	Functions *********//
	static CryptoScheme* fromFile(char* str);
	static char* toFile(char* algoritm, char* mode, unsigned char * iv, unsigned char *flid, unsigned char *tag);
	static char* toFile(CryptoScheme * c) { return toFile(c->algorithm, c->mode, c->iv, c->flid, c->tag); }
};

