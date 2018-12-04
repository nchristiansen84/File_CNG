///
// File: main.cpp
// 
// Author: Nate Christiansen
// Date: 11-30-2018
//   Added initial code for taking in CLI arguments and checking them.
//   Added -t which allows you to run a test to make sure a string can 
//     be encrypted, then decrypted and matches the original string.
//   Addded -p which allows the user to specify a path to a file that will
//     be in place encrypted (-e) or decrypted (-d) with the specified key (-k).
// 
// Author: Nate Christiansen
// Date: 12-03-2018
//   Updated -p to also work with directories instead of only files.
//   Added -r which allows the user to specify recursively encrypt or 
//     decrypt the contents of a directoty specified with -p. If -p is 
//     the path to a file and -r is used, the -r does nothing.
///
#include <stdio.h>
#include <Windows.h>
#include <shlwapi.h> // PathFileExists, PathIsDirectory
#include "Crypto_CNG.h"

///
// Gets the file size for the FilePath specified and put the file size into the OutFileSize param
// 
// Params:
//   FilePath     - The path to the file to get the size of
//   OutFileSize  - The file size will be put in this variable
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD getFileSize(PCWCH FilePath, PLARGE_INTEGER OutFileSize)
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	DWORD error = ERROR_SUCCESS;

	// Open handle to FilePath
	handle = CreateFileW( FilePath,
	                      GENERIC_READ,
	                      FILE_SHARE_READ|FILE_SHARE_WRITE,
	                      nullptr,
	                      OPEN_EXISTING,
	                      0,
	                      nullptr );
	if(handle == INVALID_HANDLE_VALUE){
		error = GetLastError();
		printf("Failed to open file. Error[%lu]\n", error);
		return error;
	}

	// Gets the FilePath size
	if(!GetFileSizeEx(handle, OutFileSize)){
		error = GetLastError();
		printf("Failed to get the file size. Error[%lu]\n", error);
		goto out;
	}

out:

	// Cleanup
	if(handle != INVALID_HANDLE_VALUE){
		CloseHandle(handle);
	}

	return error;
}

///
// Reads from the file specified with FilePath and puts the data into the OutBuffer param
// 
// Params:
//   FilePath      - The path to the file which will be read
//   Offset        - The offset to start reading from
//   OutBuffer     - The buffer to read the data into
//   OutBufferLen  - The length of the output buffer
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD readFile(PCWCH FilePath, DWORD Offset, PUCHAR OutBuffer, DWORD OutBufferLen)
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	OVERLAPPED ol = { 0 };
	DWORD bytesRead = 0, bytesTransferred = 0, error = ERROR_SUCCESS;

	// Fill out overlapped struct
	ol.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	ol.Offset = Offset;

	// Open handle to FilePath
	handle = CreateFileW( FilePath, 
	                      GENERIC_READ, 
	                      0, 
	                      nullptr, 
	                      OPEN_EXISTING, 
	                      FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED| FILE_FLAG_NO_BUFFERING,
	                      nullptr );
	if(handle == INVALID_HANDLE_VALUE){
		error = GetLastError();
		printf("Failed to open file. Error[%lu]\n", error);
		return error;
	}

	// Read from Offset of FilePath
	if(!ReadFile(handle, OutBuffer, OutBufferLen, &bytesRead, &ol)){
		error = GetLastError();
		if(error == ERROR_IO_PENDING){
			if(!GetOverlappedResult(handle, &ol, &bytesTransferred, TRUE))
			{
				error = GetLastError();
				printf("Failed to read from file. Error[%lu]\n", error);
				goto out;
			}

			error = ERROR_SUCCESS;
		}else{
			printf("Failed to read from file. Error[%lu]\n", error);
			goto out;
		}
	}

out:

	// Cleanup
	if(handle != INVALID_HANDLE_VALUE){
		CloseHandle(handle);
	}

	return error;
}

///
// Writes the data in InBuffer to the file specified with FilePath
// 
// Params:
//   FilePath     - The path to the file which will be written
//   Offset       - The offset to start writing to
//   InBuffer     - The buffer to write the data from
//   InBufferLen  - The length of the input buffer
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD writeFile(PCWCH FilePath, DWORD Offset, PUCHAR InBuffer, DWORD InBufferLen)
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	OVERLAPPED ol = { 0 };
	DWORD bytesWritten = 0, bytesTransferred = 0, error = ERROR_SUCCESS;

	// Fill out overlapped struct
	ol.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	ol.Offset = Offset;

	// Open handle to FilePath
	handle = CreateFileW( FilePath,
	                      GENERIC_WRITE,
	                      0,
	                      nullptr,
	                      OPEN_EXISTING,
	                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING,
	                      nullptr );
	if(handle == INVALID_HANDLE_VALUE){
		error = GetLastError();
		printf("Failed to open file. Error[%lu]\n", error);
		return error;
	}

	// Read from Offset of FilePath
	if(!WriteFile(handle, InBuffer, InBufferLen, &bytesWritten, &ol)){
		error = GetLastError();
		if(error == ERROR_IO_PENDING){
			if(!GetOverlappedResult(handle, &ol, &bytesTransferred, TRUE))
			{
				error = GetLastError();
				printf("Failed to write to file. Error[%lu]\n", error);
				goto out;
			}

			error = ERROR_SUCCESS;
		}
		else{
			printf("Failed to write to file. Error[%lu]\n", error);
			goto out;
		}
	}

out:

	// Cleanup
	if(handle != INVALID_HANDLE_VALUE){
		CloseHandle(handle);
	}

	return error;
}

///
// Encryptes the FilePath specified with the Key provided
// 
// Params:
//   FilePath  - The path to the file which will be encrypted
//   Key       - The key used to encrypt the file
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD encryptFile(PCWCH FilePath, PCWCH Key)
{
	PCRYPTO_CTX cryptoCtx = nullptr;
	PUCHAR buffer = nullptr;
	ULONG bufferLen = BLOCKSIZE;
	LONGLONG offset = 0;
	LARGE_INTEGER fileSize;
	DWORD error = ERROR_SUCCESS;
	NTSTATUS status;

	// Gets the FilePath size
	error = getFileSize(FilePath, &fileSize);
	if(error != ERROR_SUCCESS){
		goto out;
	}

	// Allocate memory for buffer and context
	buffer = (PUCHAR)malloc(bufferLen + 1);
	cryptoCtx = (PCRYPTO_CTX)malloc(sizeof(CRYPTO_CTX));
	if(!(cryptoCtx || buffer)){
		error = ERROR_NOT_ENOUGH_MEMORY;
		printf("Failed to allocate memory. Error[%lu]\n", error);
		goto out;
	}

	// Init context
	status = InitCtx(cryptoCtx, Key);
	if(!BCRYPT_SUCCESS(status)){
		error = ERROR_FUNCTION_FAILED;
		printf("Failed to initialize context. Error[%lu]\n", error);
		goto out;
	}

	// Loop over entire file
	while(offset < fileSize.QuadPart){
		ULONG bytesTransformed = 0;

		// Clear buffer
		memset(buffer, 0, bufferLen);

		// Read BLOCKSIZE of data from offset of FilePath
		error = readFile(FilePath, (DWORD)offset, buffer, bufferLen);
		if(error != ERROR_SUCCESS){
			goto out;
		}

		// Transform Data
		status = EncryptData(cryptoCtx, buffer, bufferLen, buffer, &bytesTransformed);
		if(!BCRYPT_SUCCESS(status)){
			error = ERROR_FUNCTION_FAILED;
			printf("Failed to encrypt data. Error[%lu]\n", error);
			goto out;
		}

		// Write BLOCKSIZE of data to offset of FilePath
		error = writeFile(FilePath, (DWORD)offset, buffer, bufferLen);
		if(error != ERROR_SUCCESS){
			goto out;
		}

		// Increase offset
		offset += bufferLen;
	}

out:

	// Cleanup
	if(cryptoCtx){
		CleanupCtx(cryptoCtx);
		free(cryptoCtx);
	}
	if(buffer){
		free(buffer);
	}

	return error;
}

///
// Decryptes the FilePath specified with the Key provided
// 
// Params:
//   FilePath  - The path to the file which will be decrypted
//   Key       - The key used to decrypt the file
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD decryptFile(PCWCH FilePath, PCWCH Key)
{
	PCRYPTO_CTX cryptoCtx = nullptr;
	PUCHAR buffer = nullptr;
	ULONG bufferLen = BLOCKSIZE;
	LONGLONG offset = 0;
	LARGE_INTEGER fileSize;
	DWORD error = ERROR_SUCCESS;
	NTSTATUS status;

	// Gets the FilePath size
	error = getFileSize(FilePath, &fileSize);
	if(error != ERROR_SUCCESS){
		goto out;
	}

	// Allocate memory for buffer and context
	buffer = (PUCHAR)malloc(bufferLen + 1);
	cryptoCtx = (PCRYPTO_CTX)malloc(sizeof(CRYPTO_CTX));
	if(!(cryptoCtx || buffer)){
		error = ERROR_NOT_ENOUGH_MEMORY;
		printf("Failed to allocate memory. Error[%lu]\n", error);
		goto out;
	}

	// Init context
	status = InitCtx(cryptoCtx, Key);
	if(!BCRYPT_SUCCESS(status)){
		error = ERROR_FUNCTION_FAILED;
		printf("Failed to initialize context. Error[%lu]\n", error);
		goto out;
	}

	// Loop over entire file
	while(offset < fileSize.QuadPart){
		ULONG bytesTransformed = 0;

		// Clear buffer
		memset(buffer, 0, bufferLen);

		// Read BLOCKSIZE of data from offset of FilePath
		error = readFile(FilePath, (DWORD)offset, buffer, bufferLen);
		if(error != ERROR_SUCCESS){
			goto out;
		}

		// Transform Data
		status = DecryptData(cryptoCtx, buffer, bufferLen, buffer, &bytesTransformed);
		if(!BCRYPT_SUCCESS(status)){
			error = ERROR_FUNCTION_FAILED;
			printf("Failed to decrypt data. Error[%lu]\n", error);
			goto out;
		}

		// Write BLOCKSIZE of data to offset of FilePath
		error = writeFile(FilePath, (DWORD)offset, buffer, bufferLen);
		if(error != ERROR_SUCCESS){
			goto out;
		}

		// Increase offset
		offset += bufferLen;
	}

out:

	// Cleanup
	if(cryptoCtx){
		CleanupCtx(cryptoCtx);
		free(cryptoCtx);
	}
	if(buffer){
		free(buffer);
	}

	return error;
}

///
// Encryptes the contents of the DirPath specified with the Key provided
// 
// Params:
//   DirPath    - The path to the dir which will be encrypted
//   Key        - The key used to encrypt the contents
//   Recursive  - If true, encrypts contents of subdirectories
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD encryptDirectory(PCWCH DirPath, PCWCH Key, bool Recursive)
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW data = { 0 };
	PWCHAR dir = nullptr;
	size_t dirLen = (wcslen(DirPath) + 3)*sizeof(WCHAR);
	DWORD error = ERROR_SUCCESS;

	// Allocate memory for DirPath + '\*'
	dir = (PWCHAR)calloc(dirLen, sizeof(WCHAR));
	if(!dir){
		error = ERROR_NOT_ENOUGH_MEMORY;
		printf("Failed to allocate memory. Error[%lu]\n", error);
		return error;
	}

	// Add "\*" to DirPath
	memcpy(dir, DirPath, dirLen);
	wcscat_s(dir, dirLen, L"\\*");

	handle = FindFirstFileW(dir, &data);
	if(handle == INVALID_HANDLE_VALUE){
		error = GetLastError();
		printf("Failed to find files in directory[%ws]. Error[%lu]\n", dir, error);
		return error;
	}

	printf("Entering: %ws\\\n", DirPath);
	do{
		if(!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L"..")){ // Ignore if \. or \..
			continue;
		}

		PWCHAR subPath = nullptr;
		size_t subPathLen = wcslen(DirPath) + wcslen(data.cFileName) + 2; // +2 for slash and null

		// Allocate memory for subPath
		subPath = (PWCHAR)calloc(subPathLen, sizeof(WCHAR));
		if(!subPath){
			error = ERROR_NOT_ENOUGH_MEMORY;
			printf("Failed to allocate memory. Error[%lu]\n", error);
			goto out;
		}
		swprintf_s(subPath, subPathLen, L"%ws\\%ws", DirPath, data.cFileName);

		if(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){ // Check for directory
			// Recursively encrypt subdirectories
			if(Recursive){
				error = encryptDirectory(subPath, Key, Recursive);
				if(error != ERROR_SUCCESS){
					free(subPath);
					printf("Failed to encrypt directory.\n");
					goto out;
				}
			}
		}else if(!(data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM // Ignore system files
		          || data.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE // Ignore sparse files
		          || data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT // Ignore reparse points/symbolic links
		          || data.dwFileAttributes & FILE_ATTRIBUTE_READONLY)){ // Ignore readonly files
			// Encrypt files in directory
			error = encryptFile(subPath, Key);
			if(error != ERROR_SUCCESS){
				free(subPath);
				printf("Failed to encrypt file[%ws].\n", subPath);
				goto out;
			}
			printf("  Encrypted - \"%ws\"\n", data.cFileName);
		}
		else{
			printf("  Ignored   - \"%ws\"\n", data.cFileName);
		}

		// Cleanup
		memset(&data, 0, sizeof(WIN32_FIND_DATAW));
		free(subPath);
	} while(FindNextFileW(handle, &data)); // Finds the next file in the directory
	printf("Finished: %ws\\\n", DirPath);

	// Check if stopped interating through directory because of failure or no more files
	error = GetLastError();
	if(!(error == ERROR_NO_MORE_FILES || error == ERROR_SUCCESS)){
		printf("Failed to find all files in directory[%ws]. Error[%lu]\n", dir, error);
		goto out;
	}
	error = ERROR_SUCCESS;

out:

	// Cleanup
	if(dir){
		free(dir);
	}
	if(handle != INVALID_HANDLE_VALUE){
		FindClose(handle);
	}

	return error;
}

///
// Decryptes the contents of the DirPath specified with the Key provided
// 
// Params:
//   DirPath    - The path to the dir which will be decrypted
//   Key        - The key used to decrypt the contents
//   Recursive  - If true, decrypts contents of subdirectories
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD decryptDirectory(PCWCH DirPath, PCWCH Key, bool Recursive)
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW data = { 0 };
	PWCHAR dir = nullptr;
	size_t dirLen = (wcslen(DirPath) + 3) * sizeof(WCHAR);
	DWORD error = ERROR_SUCCESS;

	// Allocate memory for DirPath + '\*'
	dir = (PWCHAR)calloc(dirLen, sizeof(WCHAR));
	if(!dir){
		error = ERROR_NOT_ENOUGH_MEMORY;
		printf("Failed to allocate memory. Error[%lu]\n", error);
		return error;
	}

	// Add "\*" to DirPath
	memcpy(dir, DirPath, dirLen);
	wcscat_s(dir, dirLen, L"\\*");

	handle = FindFirstFileW(dir, &data);
	if(handle == INVALID_HANDLE_VALUE){
		error = GetLastError();
		printf("Failed to find files in directory[%ws]. Error[%lu]\n", dir, error);
		return error;
	}

	printf("Entering: %ws\\\n", DirPath);
	do{
		if(!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L"..")){ // Ignore if \. or \..
			continue;
		}

		PWCHAR subPath = nullptr;
		size_t subPathLen = wcslen(DirPath) + wcslen(data.cFileName) + 2; // +2 for slash and null

		// Allocate memory for subPath
		subPath = (PWCHAR)calloc(subPathLen, sizeof(WCHAR));
		if(!subPath){
			error = ERROR_NOT_ENOUGH_MEMORY;
			printf("Failed to allocate memory. Error[%lu]\n", error);
			goto out;
		}
		swprintf_s(subPath, subPathLen, L"%ws\\%ws", DirPath, data.cFileName);

		if(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){ // Check for directory
			// Recursively decrypt subdirectories
			if(Recursive){
				error = decryptDirectory(subPath, Key, Recursive);
				if(error != ERROR_SUCCESS){
					free(subPath);
					printf("Failed to decrypt directory.\n");
					goto out;
				}
			}
		}
		else if( !(data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM // Ignore system files
		         || data.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE // Ignore sparse files
		         || data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT // Ignore reparse points/symbolic links
		         || data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ){ // Ignore readonly files
			// Decrypt files in directory
			error = decryptFile(subPath, Key);
			if(error != ERROR_SUCCESS){
				free(subPath);
				printf("Failed to decrypt file[%ws].\n", subPath);
				goto out;
			}
			printf("  Decrypted - \"%ws\"\n", data.cFileName);
		}
		else{
			printf("  Ignored   - \"%ws\"\n", data.cFileName);
		}

		// Cleanup
		memset(&data, 0, sizeof(WIN32_FIND_DATAW));
		free(subPath);
	} while(FindNextFileW(handle, &data)); // Finds the next file in the directory
	printf("Finished: %ws\\\n", DirPath);

	// Check if stopped interating through directory because of failure or no more files
	error = GetLastError();
	if(!(error == ERROR_NO_MORE_FILES || error == ERROR_SUCCESS)){
		printf("Failed to find all files in directory[%ws]. Error[%lu]\n", dir, error);
		goto out;
	}
	error = ERROR_SUCCESS;

out:

	// Cleanup
	if(dir){
		free(dir);
	}
	if(handle != INVALID_HANDLE_VALUE){
		FindClose(handle);
	}

	return error;
}

///
// Test encrypt, decrypt, then compares orig data to decrypted data.
// 
// Params:
//   None
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD test()
{
	PCRYPTO_CTX cryptoCtx = nullptr;
	PUCHAR orig = (PUCHAR)calloc(BLOCKSIZE, sizeof(UCHAR));
	PUCHAR enc = (PUCHAR)calloc(BLOCKSIZE, sizeof(UCHAR));
	PUCHAR dec = (PUCHAR)calloc(BLOCKSIZE, sizeof(UCHAR));
	PCWCH key = L"1234567890abcdef1234567890abcdef";
	ULONG bufLen = (ULONG)strlen("This is a test!?");
	ULONG bytesTransformed = 0;
	DWORD error = ERROR_SUCCESS;
	NTSTATUS status;

	memcpy(orig, "This is a test!?", bufLen);

	if(!orig || !enc || !dec){
		printf("Failed to allocate memory.\n");
		error = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	// Allocate memory for context
	cryptoCtx = (PCRYPTO_CTX)malloc(sizeof(CRYPTO_CTX));
	if(!cryptoCtx){
		printf("Failed to allocate memory for context.\n");
		error = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	// Init context
	status = InitCtx(cryptoCtx, key);
	if(!BCRYPT_SUCCESS(status)){
		printf("Failed to initialize context.\n");
		error = ERROR_FUNCTION_FAILED;
		goto out;
	}

	// Transform Data
	status = EncryptData(cryptoCtx, orig, bufLen, enc, &bytesTransformed);
	if(!BCRYPT_SUCCESS(status)){
		printf("Failed to encrypt data.\n");
		error = ERROR_FUNCTION_FAILED;
		goto out;
	}

	// Print success with original string and encrypted string
	printf("Successfully encrypted [%s] to [", orig);
	for(ULONG i = 0; i < bufLen; i++){
		putchar(enc[i]);
	}
	printf("]\n");

	bytesTransformed = 0;
	// Transform Data
	status = DecryptData(cryptoCtx, enc, bufLen, dec, &bytesTransformed);
	if(!BCRYPT_SUCCESS(status)){
		printf("Failed to decrypt data.\n");
		error = ERROR_FUNCTION_FAILED;
		goto out;
	}

	// Prints success with encrypted string and decrypted string
	printf("Successfully decrypted [");
	for(ULONG i = 0; i < bufLen; i++){
		putchar(enc[i]);
	}
	printf("] to [%s]\n", dec);

	// Compared original string to decrypted string
	if(memcmp(orig, dec, bufLen)){
		printf("Failed: Original string didn't match decrypted string\n");
		error = ERROR_FUNCTION_FAILED;
		goto out;
	}
	printf("Passed: Original string matched decrypted string. [%s] - [%s]\n", orig, dec);

out: 

	// Cleanup
	if(orig){
		free(orig);
	}
	if(enc){
		free(enc);
	}
	if(dec){
		free(dec);
	}
	if(cryptoCtx){
		// Cleanup CryptoCtx
		status = CleanupCtx(cryptoCtx);
		if(!BCRYPT_SUCCESS(status)){
			printf("Failed to cleanup context.\n");
			error = ERROR_FUNCTION_FAILED;
			goto out;
		}
		free(cryptoCtx);
	}

	return ERROR_SUCCESS;
}

///
// Checks if the Path provided by the user is valid.
// 
// Params:
//   Path - The path to the file or directory being transformed
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD isValidPath(PCWCH Path)
{
	if(!PathFileExistsW(Path)){
		DWORD error = GetLastError();
		printf("Failed to find the path[%ws]. Error[%lu]\n", Path, error);
		return error;
	}

	return ERROR_SUCCESS;
}

///
// Checks if the Key provided by the user is valid.
// 
// Params:
//   Key - The key which will be used to transform the data
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD isValidKey(PCWCH Key)
{
	// Check that the length of the Key is 32 characters
	if(wcslen(Key) != 32){
		printf("Invalid key: Must be 32 characters.\n");
		return ERROR_BAD_LENGTH;
	}

	return ERROR_SUCCESS;
}

///
// Print for when there is an invalid argument passed to this program.
// 
// Params:
//   None
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD invalidArgPrint()
{
	printf("Invalid argument(s).\n");
	printf("Use \"File_CNG.exe [-h,-?,?]\" for usage information.\n");
	return ERROR_BAD_ARGUMENTS;
}

///
// Prints the help/usage information to the user.
// 
// Params:
//   None
// 
// Return:
//   Returns DWORD of error. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
DWORD helpPrint()
{
	printf("Argument types will be indicated with [type]\n");
	printf("  [STR]  - String\n");
	printf("  [CHAR] - Character\n");
	printf("  [INT]  - Integer\n");
	putchar('\n');
	printf("File_CNG.exe usage:\n");
	printf("  -e               Encrypt\n");
	printf("                     Must be used with -k and -p\n");
	printf("                     Optionally used with -r\n");
	printf("  -d               Decrypt\n");
	printf("                     Must be used with -k and -p\n");
	printf("                     Optionally used with -r\n");
	printf("  -k [STR]         Key used for transforming\n");
	printf("                     Must be 32 characters\n");
	printf("  -p [STR]         Path to file or directory to be transformed\n");
	printf("                     Must be absolute path\n");
	printf("  -r               Recursive\n");
	printf("  -t               Test\n");
	return ERROR_SUCCESS;
}

///
// The entry point to the program which does initial checks and decideds what should happen based on arguments passed in.
// 
// Params:
//   argc   - The number of arguments passed to the program
//   argv[] - List of arguments passed into the program from the user
// 
// Return:
//   Returns System Error Code. ERROR_SUCCESS means the function was successful, otherwise it failed.
///
int wmain(int argc, PWCHAR argv[])
{
	PCWCH key = nullptr, path = nullptr;
	bool encrypt = false, decrypt = false, recursive = false;
	DWORD error = ERROR_SUCCESS;

	// Checks if the user used help command
	if(argc < 2 || (argc == 2 && (!_wcsicmp(argv[1], L"-h") || !_wcsicmp(argv[1], L"-?") || !_wcsicmp(argv[1], L"?")))){
		return helpPrint();
	}

	// Loop through argv's to search for our arguments
	for(int i = 1; i < argc; i++){
		if(!_wcsicmp(argv[i], L"-k") && argc >= i + 1){ // Key
			error = isValidKey(argv[++i]);
			if(error != ERROR_SUCCESS)
				return error;

			key = argv[i];
		}
		else if(!_wcsicmp(argv[i], L"-p") && argc >= i + 1){ // Path to file or directory
			error = isValidPath(argv[++i]);
			if(error != ERROR_SUCCESS)
				return error;

			path = argv[i];
		}else if(!_wcsicmp(argv[i], L"-e")){ // Encrypt
			encrypt = true;
		}else if(!_wcsicmp(argv[i], L"-d")){ // Decrypt
			decrypt = true;
		}else if(!_wcsicmp(argv[i], L"-r")){ // Recursive
			recursive = true;
		}else if(!_wcsicmp(argv[i], L"-t")){ // Test
			return test();
		}else{ // Invalid Argument(s)
			return invalidArgPrint();
		}
	}

	// Checks all arguments needed to perform action were provided
	if(encrypt && key && path){ // Encrypt
		if(PathIsDirectoryW(path)){
			error = encryptDirectory(path, key, recursive);
			if(error != ERROR_SUCCESS){
				printf("Failed to encrypt directory.\n");
				return error;
			}
			printf("Successfully encrypted directory[%ws]\n", path);
		}else{
			error = encryptFile(path, key);
			if(error != ERROR_SUCCESS){
				printf("Failed to encrypt file.\n");
				return error;
			}
			printf("Successfully encrypted file[%ws]\n", path);
		}
	}
	else if(decrypt && key && path){ // Decrypt
		if(PathIsDirectoryW(path)){
			error = decryptDirectory(path, key, recursive);
			if(error != ERROR_SUCCESS){
				printf("Failed to decrypt directory.\n");
				return error;
			}
			printf("Successfully decrypted directory[%ws]\n", path);
		}else{
			error = decryptFile(path, key);
			if(error != ERROR_SUCCESS){
				printf("Failed to decrypt file.\n");
				return error;
			}
			printf("Successfully decrypted file[%ws]\n", path);
		}
	}else{ // Invalid Argument(s)
		return invalidArgPrint();
	}

	return error;
}