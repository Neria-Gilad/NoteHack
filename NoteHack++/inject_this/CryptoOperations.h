#pragma once
//******************************************************************//
//					includes & macros
//******************************************************************//
#include "CryptoScheme.h"
//#include <string>
#include "RSA_components.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif
#if defined(MBEDTLS_AES_C)
#include "mbedtls/aes.h"
#endif
#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif
#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif
#if defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/ctr_drbg.h"
#endif
#if defined(MBEDTLS_ENTROPY_C)
#include "mbedtls/entropy.h"
#endif


//******************************************************************//
//					declerations
//******************************************************************//
/**
 * \brief
 * \param scheme We use tag & iv in the function
 * \param key The key for decryption
 * \param input Enter cipher text to encrypt
 * \param len The length of the input
 * \return Decrypted text, if succeeded. NULL, if the tag is forged, or an earthquake has occured
 */
unsigned char* decrypt_gcm256_authenticate(CryptoScheme * scheme, unsigned char* key, char* input, unsigned __int64 len);
/**
 * \brief
 * \param scheme We use iv and write to tag in the function
 * \param key The key for encryption
 * \param input Enter plain text to encrypt
 * \param len The length of the input
 * \return Encrypted text
 */
unsigned char* encrypt_gcm256(CryptoScheme * scheme, unsigned char* key, char* input, unsigned __int64 len);

/**
 * \brief Decrypt information using AES-CTR
 * \param iv unsigned char[SIZEOF_IV]
 * \param key
 * \param input cipher-text
 * \param len length of the input
 * \return decrypted information, in unsigned char *, NEW initialized. remember to delete.
 */
unsigned char* decrypt_aes256_ctr(unsigned char iv[], unsigned char* key, char* input, unsigned int len);
/**
 * \brief Encrypt information using AES-CTR
 * \param iv send an unsigned char[SIZEOF_IV], will contain a random IV
 * \param key
 * \param input plain-text
 * \param len length of the input
 * \return encrypted information, in unsigned char *, NEW initialized. remember to delete.
 */
unsigned char* encrypt_aes256_ctr(unsigned char iv[], unsigned char* key, char* input, unsigned int len);
/**
 * \brief This function shuldn't be used by user. This function used in encryption and decryption functions
 * \param iv send an unsigned char[SIZEOF_IV] that contains the initialization vector
 * \param key is the password for encryption/decryption. this isn't key.
 * \param input is the input. obviously.
 * \param len is lenght of input
 */
unsigned char* _aes256_ctr_process(unsigned char *&iv, unsigned char* key, char* input, unsigned int len);

/**
 * \brief Gets a password, returns (deliberately slowly) a 32 byte key; aka derive a key
 * \param password user password. normally shorter than 200. longer would be too slow
 * \param len the length of the password
 * \param salt optional field. send char[SIZEOF_SALT]
 * \param generateSalt TRUE is you want to generate a salt, FALSE otherwise (notice that salt should be random)
 * \return 32 long derived key
 */
unsigned char* derive_key_pbkdf2(unsigned char* password, unsigned int len, unsigned char salt[], bool generateSalt = false);

//******************************************************************//
//					implementations
//******************************************************************//
unsigned char* decrypt_gcm256_authenticate(CryptoScheme * scheme, unsigned char* key, char* input, unsigned __int64 len) {
	unsigned char iv_tmp[SIZEOF_IV];
	unsigned char tag_tmp[SIZEOF_TAG];
	unsigned char * output = new unsigned char[len];

	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);
	mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);

	// we don't want to violate original iv & tag
	memcpy(iv_tmp, scheme->iv, SIZEOF_IV);
	memcpy(tag_tmp, scheme->tag, SIZEOF_TAG);

	// if isBad isn't 0, its baaad
	int isBad = mbedtls_gcm_auth_decrypt(&gcm, len, iv_tmp, SIZEOF_IV, nullptr, 0, tag_tmp, SIZEOF_TAG, (unsigned char*)input, output);

	mbedtls_gcm_free(&gcm);
	return isBad ? nullptr : output;
}

unsigned char* encrypt_gcm256(CryptoScheme * scheme, unsigned char* key, char* input, unsigned __int64 len) {
	unsigned char iv_tmp[SIZEOF_IV];
	unsigned char tag_tmp[SIZEOF_TAG];
	unsigned char * output = new unsigned char[len];

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	unsigned char randomChars[32];
	char* personalization = "a_total_random_string_gilad_wrote"; // this string can be anything (promised by mbedTls)
	int isbad = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)personalization, strlen(personalization));
	isbad |= mbedtls_ctr_drbg_random(&ctr_drbg, randomChars, SIZEOF_IV);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	if (isbad) return nullptr;//failed...

	memcpy(scheme->iv, randomChars, SIZEOF_IV);//new iv
	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);
	mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);

	//we don't want to violate iv
	memcpy(iv_tmp, scheme->iv, SIZEOF_IV);


	mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, iv_tmp, SIZEOF_IV, nullptr, 0, (unsigned char*)input, output, SIZEOF_TAG, tag_tmp);

	memcpy(scheme->tag, tag_tmp, SIZEOF_TAG);
	scheme->tag[SIZEOF_TAG] = 0; //thats ok. scheme->tag has 1 spare byte

	return output;
}

unsigned char* decrypt_aes256_ctr(unsigned char iv[], unsigned char* key, char* input, unsigned int len) {
	unsigned char* output = _aes256_ctr_process(iv, key, input, len);

	//correction of padding garbage
	const int UPPER = strlen((char*)output);
	for (int i = len; i < UPPER; ++i)
		output[i] = 0;

	return output;
}
unsigned char* encrypt_aes256_ctr(unsigned char iv[], unsigned char* key, char* input, unsigned int len) {
	//we should generate unique IV. the user send unsigned char[SIZEOF_IV]
#pragma region RANDOM_GENERATOR_FOR_IV
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	bool isBad = false;
	char* personalization = "a_total_random_string_neria_wrote_i_dont_think_its_actually_random"; // this string can be anything (promised by mbedTls)
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)personalization, strlen(personalization)))
		isBad = true;
	if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, SIZEOF_IV))
		isBad = true;
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	if (isBad)
		return nullptr;
#pragma endregion

	return _aes256_ctr_process(iv, key, input, len);
}
unsigned char* _aes256_ctr_process(unsigned char * &iv, unsigned char* key, char* input, unsigned int len) {
	//assumming iv len is 16
	unsigned char streamBlock[16384]; //tmp string for mbedTls function. used as cache. idk spesipic size, googgle either.
	unsigned char _iv[16]; //we use tmp iv because iv is incremented
	mbedtls_aes_context aes;
	size_t offset = 0;

	memcpy(_iv, iv, SIZEOF_IV);

	unsigned char* output = new unsigned char[len];
	mbedtls_aes_setkey_enc(&aes, key, 256);
	mbedtls_aes_crypt_ctr(&aes, len, &offset, _iv, streamBlock, (unsigned char*)input, output);

	mbedtls_aes_free(&aes);
	return output;
}

unsigned char* derive_key_pbkdf2(unsigned char* password, unsigned int len, unsigned char salt[], bool generateSalt) {
	unsigned char* output = nullptr;
	if (generateSalt) {
#pragma region RANDOM_GENERATOR_FOR_SALT
		mbedtls_entropy_context entropy;
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_context ctr_drbg;
		mbedtls_ctr_drbg_init(&ctr_drbg);
		char* personalization = "a_total_random_string_neria_wrote_i_dont_think_its_actually_random"; // this string can be anything (promised by mbedTls)
		bool isBad = false;
		if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)personalization, 67)) // 67 is len of personalization
			isBad = true;
		if (mbedtls_ctr_drbg_random(&ctr_drbg, salt, SIZEOF_SALT))
			isBad = true;
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);

		if (isBad)
			return nullptr;
#pragma endregion
	}

	output = new unsigned char[MACRO32];
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_pkcs5_pbkdf2_hmac(
		&ctx,
		password, len,
		salt, SIZEOF_SALT,
		KDF_ITER_NUM,
		MACRO32, output
	);
	mbedtls_md_free(&ctx);
	return output;
}