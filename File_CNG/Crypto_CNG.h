#ifndef _CRYPTO_CNG_H_
#define _CRYPTO_CNG_H_

#include <Bcrypt.h>

///  ---Constants---  ///
#define BLOCKSIZE    512
#define KEY_MAX_LEN  64
#define IV_MAX_LEN   64
#define IV           L"DEFEC7EDCE11BED5"
#define IV_LEN       16

///  ---Structs---  ///

// Struct to hold crypto context
typedef struct _CRYPTO_CTX
{
	BCRYPT_ALG_HANDLE AlgHandle;
	BCRYPT_KEY_HANDLE KeyHandle;
	UCHAR Key[KEY_MAX_LEN];
	ULONG KeyLen;
	UCHAR Iv[IV_MAX_LEN];
	ULONG IvLen;
} CRYPTO_CTX, *PCRYPTO_CTX;

///  ---Functions---  ///

// Initialize CRYPTO_CTX struct
NTSTATUS InitCtx(PCRYPTO_CTX CryptoCtx, PCWCH Key);

// Cleans up CRYPTO_CTX struct
NTSTATUS CleanupCtx(PCRYPTO_CTX CryptoCtx);

// Encrypts InBuf data into OutBuf
NTSTATUS EncryptData(PCRYPTO_CTX CryptoCtx, PUCHAR InBuf, ULONG InBufLen, PUCHAR OutBuf, PULONG BytesTransformed);

// Decrypts InBuf data into OutBuf
NTSTATUS DecryptData(PCRYPTO_CTX CryptoCtx, PUCHAR InBuf, ULONG InBufLen, PUCHAR OutBuf, PULONG BytesTransformed);

#endif