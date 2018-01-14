//******************************************************************//
//					includes & macros
//******************************************************************//
#include "stdafx.h"
#include "CryptoScheme.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif
#if defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/ctr_drbg.h"
#endif
#if defined(MBEDTLS_ENTROPY_C)
#include "mbedtls/entropy.h"
#endif

//******************************************************************//
//					implementations
//******************************************************************//
CryptoScheme::CryptoScheme(const char* algorithm, const char* mode, const char* iv, const char* flid, const char* tag) {
	memcpy(this->algorithm, algorithm, MACRO16);
	memcpy(this->mode, mode, MACRO16);
	memcpy(this->iv, iv, SIZEOF_IV);
	memcpy(this->flid, flid, SIZEOF_ID);
	memcpy(this->tag, tag, SIZEOF_TAG);

	this->algorithm[MACRO16] = 0; // algorithm and mode are size 17
	this->mode[MACRO16] = 0;
}
CryptoScheme::CryptoScheme() {
#pragma region RANDOM
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	unsigned char randomChars[32];
	char* personalization = "a_total_random_string_neria_wrote"; // this string can be anything (promised by mbedTls)
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)personalization, strlen(personalization)))
		goto exit;
	if (mbedtls_ctr_drbg_random(&ctr_drbg, randomChars, 32))
		goto exit;
#pragma endregion

	strcpy_s(this->algorithm, MACRO16 + 1, "AES256");
	strcpy_s(this->mode, MACRO16 + 1, "GCM");
	memcpy(this->iv, randomChars, SIZEOF_IV);
	memcpy(this->flid, randomChars + MACRO16, SIZEOF_ID);
exit:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}
CryptoScheme::~CryptoScheme() {}

CryptoScheme* CryptoScheme::fromFile(char* str) {
	char son[5][MACRO16 + 1]; // was 64+1. shouldn't be any problems 
	char checkstr[11] = "algorithm:";

	for (int j = 0; j < 10; ++j)
		if (str[j] != checkstr[j]) return nullptr;

	int i = 29;
	for (int j = 0; j < 16; ++j, ++i)
		son[2][j] = str[i];//iv

	i += 6;

	for (int j = 0; j < 16; ++j, i++)
		son[3][j] = str[i]; //id

	i += 5;

	for (int j = 0; j < MACRO16; ++j, i++)
		son[4][j] = str[i]; // tag

	return new CryptoScheme(
		"AES256", "GCM", son[2], son[3], son[4]);
}

char* CryptoScheme::toFile(char* algoritm, char* mode, unsigned char* iv, unsigned char* flid, unsigned char* tag) {
	char* str = new char[200];
	char test[] = "algorithm:AES256;mode:GCM;iv:";
	char test2[] = ";flid:";
	char test3[] = ";tag:";
	int i = 0;
	for (; i < 29; ++i)
		str[i] = test[i]; // cpy the string "algorithm:AES256;mode:GCM;iv:"
	for (int j = 0; j < SIZEOF_IV; ++j, ++i)
		str[i] = iv[j];
	for (int j = 0; j < 6; ++j, i++)
		str[i] = test2[j]; // cpy the string ";flid:" 
	for (int j = 0; j < SIZEOF_ID; ++j, i++)
		str[i] = flid[j];
	for (int j = 0; j < 5; ++j, i++)
		str[i] = test3[j]; // cpy the string ";tag:"
	for (int j = 0; j < SIZEOF_TAG; ++j, i++)
		str[i] = tag[j];
	str[i] = ';';
	return str;
}
