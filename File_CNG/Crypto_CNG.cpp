///
// File: Crypto_CNG.cpp
// 
// Author: Nate Christiansen
// Date: 11-30-2018
//   Added code to init, cleanup, encrypt, and decrypt
///
#include <Windows.h>
#include "Crypto_CNG.h"

///
// Initializes crypto context
// 
// Params:
//   CryptoCtx  - Pointer to CryptoCtx struct which will be initialized
//   Key        - Used to generate key object for symmetrical key encryption algorithm
// 
// Return:
//   Returns NTSTATUS. STATUS_SUCCESS means function was successful, otherwise it failed.
///
NTSTATUS InitCtx(PCRYPTO_CTX CryptoCtx, PCWCH Key)
{
	NTSTATUS status;

	// Sets Key value in context
	CryptoCtx->KeyLen = (ULONG)wcslen(Key);
	memcpy_s(CryptoCtx->Key, CryptoCtx->KeyLen, Key, CryptoCtx->KeyLen);

	// Sets IV value in context
	CryptoCtx->IvLen = IV_LEN;
	memcpy_s(CryptoCtx->Iv, CryptoCtx->IvLen, IV, CryptoCtx->IvLen);

	// Opens handle CNG algorithm provider
	status = BCryptOpenAlgorithmProvider(&CryptoCtx->AlgHandle, BCRYPT_AES_ALGORITHM, nullptr, 0);
	if(!BCRYPT_SUCCESS(status)){
		return status;
	}

	// Creates a key object from Key for symmetrical key encryption algorithm
	status = BCryptGenerateSymmetricKey(CryptoCtx->AlgHandle, &CryptoCtx->KeyHandle, nullptr, 0, CryptoCtx->Key, CryptoCtx->KeyLen, 0);
	if(!BCRYPT_SUCCESS(status)){
		return status;
	}

	return status;
}

///
// Cleans up crypto context
// 
// Params:
//   CryptoCtx  - Pointer to CryptoCtx struct which will be cleaned up
// 
// Return:
//   Returns NTSTATUS. STATUS_SUCCESS means function was successful, otherwise it failed.
///
NTSTATUS CleanupCtx(PCRYPTO_CTX CryptoCtx)
{
	NTSTATUS status;

	// Destroys key object
	status = BCryptDestroyKey(CryptoCtx->KeyHandle);
	if(!BCRYPT_SUCCESS(status)){
		return status;
	}

	// Closes handle to CNG algorithm provider
	status = BCryptCloseAlgorithmProvider(CryptoCtx->AlgHandle, 0);
	if(!BCRYPT_SUCCESS(status)){
		return status;
	}

	return status;
}

///
// Encrypts data from InBuf into OutBuf
// 
// Params:
//   CryptoCtx         - Pointer to CryptoCtx struct which will be used for encryption
//   InBuf             - Plaintext data to be encrypted
//   InBufLen          - Length of InBuf
//   OutBuf            - Empty string to receive encrypted data from InBuf
//   BytesTransformed  - Number of bytes written to OutBuf
// 
// Return:
//   Returns NTSTATUS. STATUS_SUCCESS means function was successful, otherwise it failed.
///
NTSTATUS EncryptData(PCRYPTO_CTX CryptoCtx, PUCHAR InBuf, ULONG InBufLen, PUCHAR OutBuf, PULONG BytesTransformed)
{
	ULONG bytesTransformedTemp = 0;
	UCHAR iv[IV_MAX_LEN];
	ULONG ivLen = CryptoCtx->IvLen;
	NTSTATUS status = 0; // STATUS_SUCCESS

	// Loops over InBuf
	while(*BytesTransformed < InBufLen){
		memcpy(iv, CryptoCtx->Iv, ivLen);

		// Encrypts data in InBuf
		status = BCryptEncrypt(CryptoCtx->KeyHandle, InBuf + *BytesTransformed, BLOCKSIZE, nullptr, iv, ivLen, OutBuf + *BytesTransformed, BLOCKSIZE, &bytesTransformedTemp, 0);
		if(!BCRYPT_SUCCESS(status)){
			return status;
		}

		*BytesTransformed += bytesTransformedTemp;
	}

	return status;
}

///
// Decrypts data from InBuf into OutBuf
// 
// Params:
//   CryptoCtx         - Pointer to CryptoCtx struct which will be used for decryption
//   InBuf             - Encrypted data to be decrypted
//   InBufLen          - Length of InBuf
//   OutBuf            - Empty string to receive plaintext data from InBuf
//   BytesTransformed  - Number of bytes written to OutBuf
// 
// Return:
//   Returns NTSTATUS. STATUS_SUCCESS means function was successful, otherwise it failed.
///
NTSTATUS DecryptData(PCRYPTO_CTX CryptoCtx, PUCHAR InBuf, ULONG InBufLen, PUCHAR OutBuf, PULONG BytesTransformed)
{
	ULONG bytesTransformedTemp = 0;
	UCHAR iv[IV_MAX_LEN];
	ULONG ivLen = CryptoCtx->IvLen;
	NTSTATUS status = 0; // STATUS_SUCCESS

	// Loops over InBuf
	while(*BytesTransformed < InBufLen){
		memcpy(iv, CryptoCtx->Iv, ivLen);

		// Decrypts data in InBuf
		status = BCryptDecrypt(CryptoCtx->KeyHandle, InBuf + *BytesTransformed, BLOCKSIZE, nullptr, iv, ivLen, OutBuf + *BytesTransformed, BLOCKSIZE, &bytesTransformedTemp, 0);
		if(!BCRYPT_SUCCESS(status)){
			return status;
		}

		*BytesTransformed += bytesTransformedTemp;
	}

	return status;
}