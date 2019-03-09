#ifndef CRYPTOBJECT_H
#define CRYPTOBJECT_H

typedef unsigned char uchar;

class CryptObject
{
public:
    CryptObject();
	void generateKey();
    char *publickey_encode(char *sourcestr);
    char *publickey_decode(char *crypttext);
    char *privatekey_encode(char *sourcestr);
	char *privatekey_decode(char *crypttext);
	char *rsa_encrypt(char *sourcestr);
	char *rsa_decrypt(char *crypttext);
	char *rsa_encrypt_pem(char *str,char *path_key);
	char *rsa_decrypt_pem(char *str,char *path_key);

    char *aes_encode(const char *sourcestr, char *key);
    char *aes_decode(const char *crypttext, char *key);

    char *base64_encode(const char* data, int data_len);
    char *base64_decode(const char* data, int data_len, int &out_len);

	char *sha1_encode(uchar *src);
	char *evp_encode(char *src, char *Type);

    char *getAeskey() const;
    void setAeskey(char *value);

private:
    char * aeskey;
};

#endif // CRYPTOBJECT_H
