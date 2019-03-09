#include "OpenSSL.h"

#include <stdio.h>
//#include <stdlib.h>
#include <atlstr.h>
#include <tchar.h>
#include <string.h>
#include <atlstr.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#ifdef _DEBUG
#pragma comment( lib, ".\\lib\\libeay32.lib" )
#pragma comment( lib, ".\\lib\\ssleay32.lib" )
#else
#pragma comment( lib, ".\\lib\\libeay32.lib" )
#pragma comment( lib, ".\\lib\\ssleay32.lib" )
#endif

#pragma warning(disable : 4996)	// disable bogus deprecation warning

static const unsigned char publicKey[] = "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDM8+/rAsxtYeOQhDGNriWK+rPO\n\
pFrboCf+yu8PcHMacBm/+Y6RlLN8Xt3J1vxdqcWHR+ghTDYvcKN3VRUfuHW+0JDS\n\
rCxa7aOdlZCFIfK710VIGoJcvbXE+/t3xTveAcdEdUsKymW4ZBlgDIK0SgE2o3sz\n\
TssqTIRVZeHnxNs8XwIDAQAB\n\
-----END PUBLIC KEY-----\n";

static const unsigned char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXgIBAAKBgQDM8+/rAsxtYeOQhDGNriWK+rPOpFrboCf+yu8PcHMacBm/+Y6R\n\
lLN8Xt3J1vxdqcWHR+ghTDYvcKN3VRUfuHW+0JDSrCxa7aOdlZCFIfK710VIGoJc\n\
vbXE+/t3xTveAcdEdUsKymW4ZBlgDIK0SgE2o3szTssqTIRVZeHnxNs8XwIDAQAB\n\
AoGBAKP1EZ1j474tbSsTVcEN66K+5FEPUlAYU2aVWaF0R+CChVb6gX8dAmkgSzVI\n\
8yLKyeZrM9xPZ5mT9nFkcz2pBydrSj1p9EBsFYqMbuytXOM4ClHYNAwFpvMzTzkd\n\
Dqd8MttEe13tiqcYJ288uQFOz9FW8Vd3VVKlNPsr42dbsXaBAkEA+V9pstrLbN0g\n\
Fjh/zCbWlOnx3AlSfhaNji/jP5WT/G2rCrc3d6TgjGdkPHu6g8Jef47jFNBtPBKY\n\
xKotImVa7wJBANJmUUz7zjKZuwgdtrghUt2gBSgAln8Lv8mA6LOgwlJA+PzHGoLl\n\
TjCmK4cEYzni45eEac88Vdjg/JdheL1U9ZECQQCK2ciV0OPR8vHpzX3DI6D5e6Wy\n\
ufIXyOD62ckz30puFHZXWhrlYIWzR+J1FwOMV86cQehI76DTARvU7ViCPWM7AkEA\n\
zzB01UOOTWP3u0lPeslOCfMfwMG7cgaG6Y6pGOKxGUDkMEB9SfM3aU7pxD682+8j\n\
Qjzh2XLH8xezhfs1Y/S7EQJAJOcxfKu3cWY03UK1Nnsgy4O2SE0yw6J7OW1osOpv\n\
AQ1Ilrp2E8JnAJYmZEWEh9Ia+vqud3r1lebqnYfX4Qtk+w==\n\
-----END RSA PRIVATE KEY-----\n";

static const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static char find_pos(char ch)
{
    char *ptr = (char*)strrchr(base, ch);//the last position (the only) in base[]
    return (ptr - base);
}

// 打印前， 有必要转换  
void printHash(unsigned char *md, int len)  
{  
	int i = 0;  
	for (i = 0; i < len; i++)  
	{  
		printf("%02x", md[i]);  
	}  
	printf("\n");  
}  

CryptObject::CryptObject()
{

}

void CryptObject::generateKey() {

	/* 生成公钥 */
	RSA* rsa = RSA_generate_key( 1024, RSA_F4, NULL, NULL);
	BIO *bp = BIO_new( BIO_s_file() );
	BIO_write_filename( bp, "public.pem" );
	PEM_write_bio_RSAPublicKey(bp, rsa);
	BIO_free_all( bp );

	/* 生成私钥 */
	char passwd[]="2012";
	bp = BIO_new_file("private.pem", "w+");
	PEM_write_bio_RSAPrivateKey(bp, rsa, EVP_des_ede3(), (unsigned char*)passwd, 4, NULL, NULL);
	BIO_free_all( bp );
	RSA_free(rsa);

}

//公钥加密
char *CryptObject::publickey_encode(char *sourcestr)
{
    RSA *rsa = NULL;

    BIO *bio = NULL;
    if ((bio = BIO_new_mem_buf((void *)publicKey, -1)) == NULL) {
        fprintf(stderr, "Load Public Key Error!");
        return NULL;
    }

    rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa) {
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        fprintf(stderr, "%s%s%s", "load public key failed[",errBuf,"]");
        BIO_free_all(bio);
        return NULL;
    }

    char * encrypted = (char *) malloc(1000+strlen(sourcestr) * 3);
    int len = RSA_public_encrypt(strlen(sourcestr), (unsigned char *)sourcestr, (unsigned char *)encrypted, rsa, RSA_PKCS1_PADDING);
    if (len == -1) {
        fprintf(stderr, "Failed to encrypt.\n");
        RSA_free(rsa);
        BIO_free_all(bio);
        return NULL;
    }
    char * result = base64_encode(encrypted, len);

    free(encrypted);
    RSA_free(rsa);
    BIO_free_all(bio);

    return result;
}

//公钥解密
char *CryptObject::publickey_decode(char *crypttext)
{
    RSA *rsa = NULL;

    BIO *bio = NULL;
    if ((bio = BIO_new_mem_buf((void *)publicKey, -1)) == NULL) {
        fprintf(stderr, "Load Public Key Error!");
        return NULL;
    }

    rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa) {
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        fprintf(stderr, "%s%s%s", "load public key failed[",errBuf,"]");
        BIO_free_all(bio);
        return NULL;
    }

    int outlen = 0;
    char *crypted = base64_decode(crypttext, strlen(crypttext), outlen);
    char * sourcestr = (char *) malloc(1000+strlen(crypted) * 3);
    int len = RSA_public_decrypt(outlen, (unsigned char *)crypted, (unsigned char *)sourcestr, rsa, RSA_PKCS1_PADDING);
    if (len == -1) {
        fprintf(stderr, "Failed to decrypt.\n");
        RSA_free(rsa);
        BIO_free_all(bio);
        return NULL;
    }
    sourcestr[len] = '\0';

    free(crypted);
    RSA_free(rsa);
    BIO_free_all(bio);

    return sourcestr;
}

//私钥加密
char *CryptObject::privatekey_encode(char *sourcestr)
{
    RSA *rsa = NULL;

	BIO *bio = NULL;
	if ( (bio = BIO_new_mem_buf((void *)privateKey, -1)) == NULL ) {
        fprintf(stderr, "Load Private Key Error!");
        return NULL;
    }

    rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!rsa) {
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        fprintf(stderr, "%s%s%s", "load private key failed[",errBuf,"]");
        BIO_free_all(bio);
        return NULL;
    }

    char * encrypted = (char *) malloc(1000+strlen(sourcestr) * 3);
    int len = RSA_private_encrypt(strlen(sourcestr), (unsigned char *)sourcestr, (unsigned char *)encrypted, rsa, RSA_PKCS1_PADDING);
    if (len == -1) {
        fprintf(stderr, "Failed to encrypt.\n");
        RSA_free(rsa);
        BIO_free_all(bio);
        return NULL;
    }
    char * result = base64_encode(encrypted, len);

    free(encrypted);
    RSA_free(rsa);
    BIO_free_all(bio);

    return result;
}

//私钥解密
char *CryptObject::privatekey_decode(char *crypttext)
{
    RSA *rsa = NULL;

	BIO *bio = NULL;
	if ( (bio = BIO_new_mem_buf((void *)privateKey, -1)) == NULL ) {
        fprintf(stderr, "Load Private Key Error!");
        return NULL;
    }

    rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!rsa) {
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        fprintf(stderr, "%s%s%s", "load private key failed[",errBuf,"]");
        BIO_free_all(bio);
        return NULL;
    }

    int outlen = 0;
    char *crypted = base64_decode(crypttext, strlen(crypttext), outlen);
    char *sourcestr = (char *) malloc(1000+strlen(crypted) * 3);
    int len = RSA_private_decrypt(outlen, (unsigned char *)crypted, (unsigned char *)sourcestr, rsa, RSA_PKCS1_PADDING);
    if (len == -1) {
        fprintf(stderr, "Failed to decrypt.\n");
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        fprintf(stderr, "%s\n", errBuf);
        RSA_free(rsa);
        BIO_free_all(bio);
        return NULL;
    }
    sourcestr[len] = '\0';

    free(crypted);
    RSA_free(rsa);
    BIO_free_all(bio);
    return sourcestr;
}

//RSA公钥加密
char *CryptObject::rsa_encrypt(char *sourcestr){

	RSA *p_rsa = NULL;

	BIO *bio = NULL;
	if ((bio = BIO_new_mem_buf((void *)publicKey, -1)) == NULL) {
		fprintf(stderr, "Load Public Key Error!");
		return NULL;
	}

	p_rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	if (!p_rsa) {
		ERR_load_crypto_strings();
		char errBuf[512];
		ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
		fprintf(stderr, "%s%s%s", "load public key failed[",errBuf,"]");
		BIO_free_all(bio);
		return NULL;
	}

	char *p_en;
	int rsa_len; //密钥长度
	rsa_len = RSA_size(p_rsa);
	p_en = (char *)malloc(rsa_len+1);
	memset(p_en,0,rsa_len+1);
	
	int len = RSA_public_encrypt(rsa_len,(unsigned char *)sourcestr,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING);
	if (len == -1) {
		RSA_free(p_rsa);
		BIO_free_all(bio);
		return NULL;
	}
	char * result = base64_encode(p_en, len);

	RSA_free(p_rsa);
	BIO_free_all(bio);
	return result;

}
//RSA私钥解密
char *CryptObject::rsa_decrypt(char *crypttext){

	RSA *p_rsa = NULL;
	BIO *bio = NULL;
	if ( (bio = BIO_new_mem_buf((void *)privateKey, -1)) == NULL ) {
		fprintf(stderr, "Load Private Key Error!");
		return NULL;
	}
	p_rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	if (!p_rsa) {
		ERR_load_crypto_strings();
		char errBuf[512];
		ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
		fprintf(stderr, "%s%s%s", "load private key failed[",errBuf,"]");
		BIO_free_all(bio);
		return NULL;
	}

	int outlen = 0;
	char *crypted = base64_decode(crypttext, strlen(crypttext), outlen);

	char *p_de;
	int rsa_len;//密钥长度
	rsa_len = RSA_size(p_rsa);
	p_de = (char *)malloc(rsa_len+1);
	memset(p_de,0,rsa_len+1);
	int len = RSA_private_decrypt(rsa_len,(unsigned char *)crypted,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING);
	if (len == -1) {
		RSA_free(p_rsa);
		BIO_free_all(bio);
		return NULL;
	}
	RSA_free(p_rsa);
	BIO_free_all(bio);
	return p_de;

}
//RSA外置公钥加密 PUBLICKEY
char *CryptObject::rsa_encrypt_pem(char *str,char *path_key){
	char *p_en;
	RSA *p_rsa;
	FILE *file;
	int flen,rsa_len;

	//if( (file = fopen(path_key,"r")) == NULL ){
	if( fopen_s(&file, "path_key", "r") == NULL ){
		perror("open key file error");
		return NULL;    
	}

	if( ( p_rsa = PEM_read_RSA_PUBKEY( file, NULL, NULL, NULL ) ) == NULL ){
		//if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   换成这句死活通不过，无论是否将公钥分离源文件
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	flen = strlen(str);
	rsa_len = RSA_size(p_rsa);
	p_en = (char *)malloc(rsa_len+1);
	memset(p_en,0,rsa_len+1);
	if(RSA_public_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
		return NULL;
	}
	RSA_free(p_rsa);
	fclose(file);
	return p_en;
}
//RSA外置私钥解密 PRIVATEKEY
char *CryptObject::rsa_decrypt_pem(char *str,char *path_key){
	char *p_de;
	RSA *p_rsa;
	FILE *file;
	int rsa_len;
	//if( (file = fopen(path_key,"r")) == NULL ){
	if( fopen_s(&file, "path_key", "r") == NULL ){
		perror("open key file error");
		return NULL;
	}
	if( ( p_rsa = PEM_read_RSAPrivateKey( file, NULL, NULL, NULL ) ) == NULL ){
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	rsa_len = RSA_size(p_rsa);
	p_de = (char *)malloc(rsa_len+1);
	memset(p_de,0,rsa_len+1);
	if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
		return NULL;
	}
	RSA_free(p_rsa);
	fclose(file);
	return p_de;
}
//AES加密
char *CryptObject::aes_encode(const char *sourcestr, char *key = "")
{
    if (strcmp(key, "") == 0) key = aeskey;
    
    char strTempKey[AES_BLOCK_SIZE + 1] = {0};
    strcpy(strTempKey, key);
	
    int len = strlen(sourcestr);
    // unsigned char * iv= (unsigned char *)strcpy((char *)malloc(17), "6543210987654321");
    unsigned char iv[AES_BLOCK_SIZE+1] = "6543210987654321";

    unsigned char * out = (unsigned char *)malloc(1024*1024);
    if (out == NULL) {
        fprintf(stderr, "No Memory!\n");
    }
    //memset(out, 0, 1024*1024);
    AES_KEY aes;
    if(AES_set_encrypt_key((unsigned char*)strTempKey, 128, &aes) < 0)
    {
        return NULL;
    }
    int out_len = ((len - 1) / 16 + 1)* 16;
    char * sstr = (char *)malloc(sizeof(char) * out_len + 1);
    memset(sstr, (char)0x00, out_len+1);
	strcpy(sstr, sourcestr);//AES加密会报错 只能用strcpy
	//strcpy_s(sstr, strlen(sourcestr), sourcestr);
    AES_cbc_encrypt((unsigned char*)sstr, out, out_len, &aes, /*(unsigned char*)*/iv, AES_ENCRYPT);
    char * out2 = base64_encode((char *)out, out_len);
    free(out);
    free(sstr);
    return out2;
}

//AES解密
char *CryptObject::aes_decode(const char *crypttext, char *key = "")
{
    if (strcmp(key, "") == 0) key = aeskey;
    
    char strTempKey[AES_BLOCK_SIZE + 1] = {0};
    strcpy(strTempKey, key);
	
    int out_len = 0;
    unsigned char iv[AES_BLOCK_SIZE+1] = "6543210987654321";

    //fprintf(stderr, "In:%s\n", crypttext);

    char *in = base64_decode(crypttext, strlen(crypttext), out_len);
    char *out = (char *) malloc(sizeof(char) * out_len + 1);
    memset(out, 0, out_len + 1);
    AES_KEY aes;
    if(AES_set_decrypt_key((unsigned char*)strTempKey, 128, &aes) < 0)
    {
        return NULL;
    }
    //fprintf(stderr, "Outlen:%d\n", out_len);
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, out_len, &aes, (unsigned char*)iv, AES_DECRYPT);
    //fprintf(stderr, "Output:%s\n", out);
    return out;
}

//Base64编码
char *CryptObject::base64_encode(const char *data, int data_len)
{
    int prepare = 0;
        int ret_len;
        int temp = 0;
        char *ret = NULL;
        char *f = NULL;
        int tmp = 0;
        char changed[4];
        int i = 0;
        ret_len = data_len / 3;
        temp = data_len % 3;
        if (temp > 0)
        {
            ret_len += 1;
        }
        ret_len = ret_len*4 + 1;
        ret = (char *)malloc(ret_len);

        if ( ret == NULL)
        {
            printf("No enough memory.\n");
            exit(0);
        }
        memset(ret, 0, ret_len);
        f = ret;
        while (tmp < data_len)
        {
            temp = 0;
            prepare = 0;
            memset(changed, '\0', 4);
            while (temp < 3)
            {
                //printf("tmp = %d\n", tmp);
                if (tmp >= data_len)
                {
                    break;
                }
                prepare = ((prepare << 8) | (data[tmp] & 0xFF));
                tmp++;
                temp++;
            }
            prepare = (prepare<<((3-temp)*8));
            //printf("before for : temp = %d, prepare = %d\n", temp, prepare);
            for (i = 0; i < 4 ;i++ )
            {
                if (temp < i)
                {
                    changed[i] = 0x40;
                }
                else
                {
                    changed[i] = (prepare>>((3-i)*6)) & 0x3F;
                }
                *f = base[changed[i]];
                //printf("%.2X", changed[i]);
                f++;
            }
        }
        *f = '\0';

        return ret;
}
//Base64解码
char *CryptObject::base64_decode(const char *data, int data_len, int &out_len)
{
    int ret_len = (data_len / 4) * 3;
        int equal_count = 0;
        char *ret = NULL;
        char *f = NULL;
        int tmp = 0;
        int temp = 0;
        char need[3];
        int prepare = 0;
        int i = 0;
        if (*(data + data_len - 1) == '=')
        {
            equal_count += 1;
        }
        if (*(data + data_len - 2) == '=')
        {
            equal_count += 1;
        }
        if (*(data + data_len - 3) == '=')
        {//seems impossible
            equal_count += 1;
        }
        switch (equal_count)
        {
        case 0:
            ret_len += 4;//3 + 1 [1 for NULL]
            break;
        case 1:
            ret_len += 4;//Ceil((6*3)/8)+1
            break;
        case 2:
            ret_len += 3;//Ceil((6*2)/8)+1
            break;
        case 3:
            ret_len += 2;//Ceil((6*1)/8)+1
            break;
        }
        ret = (char *)malloc(ret_len);
        if (ret == NULL)
        {
            printf("No enough memory.\n");
            exit(0);
        }
        memset(ret, 0, ret_len);
        f = ret;
        while (tmp < (data_len - equal_count))
        {
            temp = 0;
            prepare = 0;
            memset(need, 0, 3);
            while (temp < 4)
            {
                if (tmp >= (data_len - equal_count))
                {
                    break;
                }
                prepare = (prepare << 6) | (find_pos(data[tmp]));
                temp++;
                tmp++;
            }
            prepare = prepare << ((4-temp) * 6);
            for (i=0; i<3 ;i++ )
            {
                if (i == temp)
                {
                    break;
                }
                *f = (char)((prepare>>((2-i)*8)) & 0xFF);
                f++;
            }
        }
        *f = '\0';
        out_len = (int)(f - ret);
        if (out_len < 0) out_len = 0;
        return ret;
}
//字串转Hex
CString ConvertCStringoHex( unsigned char *tagChar, int nLen )
{
	//转换成hex
	CString sResult = L"";
	int nLoop = 0;
	int cc = 0;
	//while( tagChar[nLoop] != '\0' )
	for ( ; nLoop<nLen; )
	{
		static const char *hex="0123456789ABCDEF";
		if( tagChar[nLoop]<127 && tagChar[nLoop]>0 ) //如果是英文字母
		{
			unsigned char chHexA = hex[((unsigned char)(tagChar[nLoop]) >> 4) & 0x0f];
			unsigned char chHexB = hex[(unsigned char)(tagChar[nLoop]) & 0x0f];
            sResult += (char)chHexA;
		    sResult += (char)chHexB;
		    nLoop++;
		}
		else //如果是汉字
		{
			cc = tagChar[nLoop];
			for(int i=0; i<2; i++)
			{
				if ( nLoop+i < nLen )
				{
					unsigned char chHexA = hex[((unsigned char)(tagChar[nLoop+i]) >> 4) & 0x0f];
					unsigned char chHexB = hex[(unsigned char)(tagChar[nLoop+i]) & 0x0f];
					sResult += (char)chHexA;
					sResult += (char)chHexB;
				}
			}
			nLoop+=2;
		}
	}
	return sResult;
}

//SHA1编码
char *CryptObject::sha1_encode(uchar *src)
{
	SHA_CTX c;
	uchar *dest = (uchar *)malloc((SHA_DIGEST_LENGTH + 1)*sizeof(uchar));
	memset(dest, 0, SHA_DIGEST_LENGTH + 1);
	if(!SHA1_Init(&c))
	{
		free(dest);
		return NULL;
	}
	SHA1_Update(&c, src, strlen((const char *)src));
	SHA1_Final(dest, &c);
	OPENSSL_cleanse(&c, sizeof(c));

	CString hexstr = ConvertCStringoHex( dest, SHA_DIGEST_LENGTH );

	//printHash(dest, SHA_DIGEST_LENGTH);

	//uchar *pstr=new char[256];    
	//byte *pb=&dest[0];
	//while(!pb)
	//	sprintf(pstr++,"%02x",*pb++);
#ifdef _UNICODE
    USES_CONVERSION;
    return T2A(hexstr.GetBuffer(0));//str;
#else
    return hexstr.GetBuffer(0);//str;
#endif
}
//EVP编码 "md4","md5","sha1","sha224","sha256","sha384","sha512"
char *CryptObject::evp_encode(char *src, char *Type)
{
	EVP_MD_CTX mdctx;
	const EVP_MD *md = NULL;

	unsigned char mdValue[EVP_MAX_MD_SIZE] = {0};
	unsigned int mdLen = 0;

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(Type);
	if(!md) // 不支持的格式
	{
		printf("Unknown Type : %s\n", Type);
		return "";
	}

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	EVP_DigestUpdate(&mdctx, src, strlen(src));
	EVP_DigestFinal_ex(&mdctx, mdValue, &mdLen);
	EVP_MD_CTX_cleanup(&mdctx);

	CString hexstr = "";
	hexstr = ConvertCStringoHex( mdValue, mdLen );
	
#ifdef _UNICODE
    USES_CONVERSION;
    return T2A(hexstr.GetBuffer(0));
#else
    return hexstr.GetBuffer(0);
#endif

	//printf("%s is ", Type);
	//char *pstr = new char[256];  
	//int j = 0;
	//for(j = 0; j < mdLen; j++)
	//{
	//	printf("%02X", mdValue[j]);
	//	sprintf(pstr++,"%02x",mdValue[j]);
	//}

}
char *CryptObject::getAeskey() const
{
    return aeskey;
}

void CryptObject::setAeskey(char *value)
{
    aeskey = value;
}

