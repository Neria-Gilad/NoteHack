#pragma once
//******************************************************************//
//					includes & macros
//******************************************************************//
#include "stdafx.h"
#include <string>
#ifndef MBEDTLS_CONFIG_FILE
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) &&     \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#endif

#ifndef B64
#define B64 520
#endif
#ifndef B32
#define B32 264
#endif
#ifndef B1
#define B1 16
#endif
#ifndef MACRO32
#define MACRO32 32
#endif
#define RSA_BYTES 256
#define KEY_SIZE 2048
#define EXPONENT 65537
#define PKSC15_HEADER_LEN 11
#define MAX_LEN_RSA (KEY_SIZE / 8) - PKSC15_HEADER_LEN - 1 //usualy 244

struct RSA_public {
	char N[B64];		/*!<  public modulus    */
	char E[B1];			/*!<  public exponent   */

	int padding;
	//there should be another field hash_id with 0 value
};

struct RSA_private {
	char good[5] = "GOOD";
	char D[B64];		/*!<  private exponent  */
	char P[B64];		/*!<  1st prime factor  */
	char Q[B64];		/*!<  2nd prime factor  */

	char DP[B64];		/*!<  D % (P - 1)       */
	char DQ[B64];		/*!<  D % (Q - 1)       */
	char QP[B64];		/*!<  1 / (Q % P)       */


};

//******************************************************************//
//					declerations
//******************************************************************//
/**
 * \brief Copy data from ctx to pub & priv
 * \param ctx mbedTLS original rsa struct
 * \param pub already initialized pointer to struct that holds public RSA information ONLY
 * \param priv already initialized pointer to struct that holds private RSA information ONLY
 */
int getMbedRSA_CTX(mbedtls_rsa_context *ctx, RSA_public *pub, RSA_private *priv);
/**
 * \brief Copy data from pub & priv to ctx
 * \param ctx already initialized pointer to mbedTLS original rsa struct
 * \param pub struct that holds public RSA information ONLY
 * \param priv struct that holds private RSA information ONLY
 * \return success is 0. every other value is error.
 */
int setMbedRSA_CTX(mbedtls_rsa_context *ctx, RSA_public *pub, RSA_private *priv);

/**
 * \brief Gets initialized pointers, returns a good randoms generated RSA key pair
 * \param pub will contain N,E ; public information
 * \param priv will contains private information
 * \return success is 0. every other value is error.
 */
int rsa_init(RSA_public *pub, RSA_private *priv);
/**
 * \brief Decrypt information using RSA PKCS#1 v1.5
 * \param pub public RSA information
 * \param priv private RSA information
 * \param input the cipher-text we want to decrypt
 * \param len the length of the cipher-text
 * \return Decrypted information. Remember to delete it after your weird use
 */
unsigned char *decrypt_rsa_pkcs15(RSA_public *pub, RSA_private *priv, char *input, unsigned int len);
/**
 * \brief Encrypt information using RSA PKCS#1 v1.5
 * \param pub public RSA information
 * \param input the plain-text we want to decrypt
 * \param len the length of the plain-text
 * \return Encrypted information. Remember to delete it after your weird use
 */
unsigned char *encrypt_rsa_pkcs15(RSA_public *pub, char *input, unsigned int len);

/**
 * \brief Gets public RSA key and char key[32], randomly generate 32 chars, encrypt it with the public key, and write it to key[32]
 * \param key we'll fill with randomly generated key. send char[32] initialized array.
 * \param pub public RSA information
 * \return success is 0. every other value is error.
 */
int init_file_key(char key[], RSA_public *pub);

//******************************************************************//
//					implementations
//******************************************************************//
int init_file_key(char key[], RSA_public *pub) {
	int ret = -1;
	unsigned char *tmp = nullptr;
#pragma region RANDOM
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	unsigned char randomChars[32];
	char personalization[] = "4_t0t4l_g3n3r1c_Str1ng_w0w_1m_shocked"; // this string can be anything (promised  mbedTls)
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)personalization, 38)) // 38 is len of personalization
		goto exit;
	if (mbedtls_ctr_drbg_random(&ctr_drbg, randomChars, 32))
		goto exit;
#pragma endregion
	tmp = encrypt_rsa_pkcs15(pub, (char *)randomChars, MACRO32);

	if (tmp) {
		memcpy(key, tmp, RSA_BYTES);
		ret = 0;
	}

exit:
	if (tmp)
		delete[] tmp;
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

int setMbedRSA_CTX(mbedtls_rsa_context *ctx, RSA_public *pub, RSA_private *priv) {
	if (!ctx)
		return -1;
	int ret = 0;

	ctx->hash_id = 0;
	if (pub) {
		ret |= mbedtls_mpi_read_string(&(ctx->N), 16, pub->N);
		ret |= mbedtls_mpi_read_string(&(ctx->E), 16, pub->E);
		ctx->padding = pub->padding;
	}
	if (priv) {
		ret |= mbedtls_mpi_read_string(&(ctx->D), 16, priv->D);
		ret |= mbedtls_mpi_read_string(&(ctx->P), 16, priv->P);
		ret |= mbedtls_mpi_read_string(&(ctx->Q), 16, priv->Q);
		ret |= mbedtls_mpi_read_string(&(ctx->DP), 16, priv->DP);
		ret |= mbedtls_mpi_read_string(&(ctx->DQ), 16, priv->DQ);
		ret |= mbedtls_mpi_read_string(&(ctx->QP), 16, priv->QP);
	}
	return ret;
}

int getMbedRSA_CTX(mbedtls_rsa_context *ctx, RSA_public *pub, RSA_private *priv) {
	if (!ctx)
		return -1;
	int ret = 0;

	size_t *olen = new size_t(0);
	if (pub) {
		ret |= mbedtls_mpi_write_string(&(ctx->N), 16, pub->N, B64, olen);
		ret |= mbedtls_mpi_write_string(&(ctx->E), 16, pub->E, B1, olen);
		pub->padding = ctx->padding;
	}
	if (priv) {
		ret |= mbedtls_mpi_write_string(&(ctx->D), 16, priv->D, B64, olen);
		ret |= mbedtls_mpi_write_string(&(ctx->P), 16, priv->P, B64, olen);
		ret |= mbedtls_mpi_write_string(&(ctx->Q), 16, priv->Q, B64, olen);

		ret |= mbedtls_mpi_write_string(&(ctx->DP), 16, priv->DP, B64, olen);
		ret |= mbedtls_mpi_write_string(&(ctx->DQ), 16, priv->DQ, B64, olen);
		ret |= mbedtls_mpi_write_string(&(ctx->QP), 16, priv->QP, B64, olen);
	}
	return ret;
}

int rsa_init(RSA_public *pub, RSA_private *priv) {
	int ret = -1;
#pragma region RANDOM
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	unsigned char randomChars[32];
	char personalization[] = "a_total_random_string_wow_im_shocked"; // this string can be anything (promised by  mbedTls)
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)personalization, 37)) // 37 is len of personalization
		goto exit;
	if (mbedtls_ctr_drbg_random(&ctr_drbg, randomChars, 32))
		goto exit;
#pragma endregion
	mbedtls_rsa_context rsa;
	mbedtls_hmac_drbg_context rng_ctx;
	const mbedtls_md_info_t *md_info;

	mbedtls_hmac_drbg_init(&rng_ctx);

	if (!(md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)))
		goto exit;

	mbedtls_hmac_drbg_seed_buf(&rng_ctx, md_info, randomChars, 32);
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	if (mbedtls_rsa_gen_key(&rsa, mbedtls_hmac_drbg_random, &rng_ctx, KEY_SIZE, EXPONENT))
		goto exit;

	// successfully generated!
	ret = getMbedRSA_CTX(&rsa, pub, priv);

exit:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_hmac_drbg_free(&rng_ctx);
	mbedtls_rsa_free(&rsa);

	return ret;
}

unsigned char* decrypt_rsa_pkcs15(RSA_public *pub, RSA_private *priv, char *input, unsigned int len) {
	unsigned int i = 0;
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	unsigned char *output = new unsigned char[256];
	const char *pers = "rsa_decrypt";

	memset(output, 0, 256);

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	int ret = mbedtls_ctr_drbg_seed(
		&ctr_drbg, mbedtls_entropy_func,
		&entropy,
		(const unsigned char *)pers,
		strlen(pers));

	if (ret)
		goto exit;

	if (ret = setMbedRSA_CTX(&rsa, pub, priv))
		goto exit;

	rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

	rsa.padding = MBEDTLS_RSA_PKCS_V15;
	ret = mbedtls_rsa_pkcs1_decrypt(
		&rsa,
		mbedtls_ctr_drbg_random,
		&ctr_drbg,
		MBEDTLS_RSA_PRIVATE,
		&i,
		(unsigned char *)input,
		output,
		256);

exit:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_rsa_free(&rsa);
	if (ret) {
		delete[] output;
		output = nullptr;
	}
	return output;
}

unsigned char *encrypt_rsa_pkcs15(RSA_public *pub, char *input, unsigned int len) {
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	unsigned char *output = new unsigned char[256];
	const char *pers = "rsa_encrypt";

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	int ret = mbedtls_ctr_drbg_seed(
		&ctr_drbg,
		mbedtls_entropy_func,
		&entropy,
		(const unsigned char *)pers,
		strlen(pers));
	if (ret)
		goto exit;

	if (ret = setMbedRSA_CTX(&rsa, pub, nullptr)) //no need for private key
		goto exit;																		   
	rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3; //len is 256

	ret = mbedtls_rsa_pkcs1_encrypt(
		&rsa,
		mbedtls_ctr_drbg_random,
		&ctr_drbg,
		MBEDTLS_RSA_PUBLIC,
		len,
		(unsigned char *)input,
		output);

exit:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_rsa_free(&rsa);
	if (ret) {
		delete[] output;
		output = nullptr;
	}
	return output;
}