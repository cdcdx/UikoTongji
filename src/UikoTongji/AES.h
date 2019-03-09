/******************************************************************************
  Copyright (c) 2012-2022, jiangkun. All rights reserved.
  File Name     : AesCBC.h
  Version       : Initial Draft
  Author        : jiangkun
  Created       : 2012/04/10
  Last Modified :
  Description   : The Cipher Block chaining(CBC) mode encryption and decryption
  Function List :
  History       :
  Date          : 2012/04/10
  Author        : jiangkun
  Modification  : Created file
******************************************************************************/

#ifndef HEADER_AES_CBC_H
#define HEADER_AES_CBC_H

#define AES_ENCRYPT	1
#define AES_DECRYPT	0

/* Because array size can't be a const in C, the following two are macros.
Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

#ifdef  __cplusplus
extern "C" {
#endif
	
	/* This should be a hidden type, but EVP requires that the size be known */
	struct aes_key_st {
#ifdef AES_LONG
		unsigned long rd_key[4 *(AES_MAXNR + 1)];
#else
		unsigned int rd_key[4 *(AES_MAXNR + 1)];
#endif
		int rounds;
	};
	typedef struct aes_key_st AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);

int AES_encrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key);
int AES_decrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key);

int AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
	const unsigned long length, const AES_KEY *key,
	unsigned char *ivec, const int enc);

class Cipher
{
public:
    Cipher();
    char *aes_encode(const char *sourcestr, char *key);
    char *aes_decode(const char *crypttext, char *key);
    char *base64_encode(const char* data, int data_len);
    char *base64_decode(const char* data, int data_len, int &out_len);

private:
    char * aeskey;
};

#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_AES_CBC_H */
