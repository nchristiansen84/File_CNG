# File_CNG

This is a project I'm working on for fun. This Windows CLI program will encrypt/decrypt a specified path with the provided key using Windows CNG. 

Currently it has to be an absolute path, and future plans to allow relative paths. I also plan to add the option for an output path so it doesn't only do in place transformation.

I still have testing to do with the initial program before I start added more stuff to it.

File_CNG.exe usage:
	-e               Encrypt
	                   Must be used with -k and -p
	                   Optionally used with -r
	-d               Decrypt
	                   Must be used with -k and -p
	                   Optionally used with -r
	-k [STR]         Key used for transforming (must be 32 characters)
	-p [STR]         Path to file or directory to be transformed (must be absolute path)
	-r               Recursive
	-t               Test

Examples:
  File_CNG.exe -t
    -> This will run a test where a string is created, encrypted, decrypted, then comapred to the original.
  File_CNG.exe -e -k 12345678901234567890123456789012 -p E:\testDir\testFile.txt
    -> This will encrypt the file specified
  File_CNG.exe -d -k 12345678901234567890123456789012 -p E:\testDir\testFile.txt
    -> This will decrypt the file specified
  File_CNG.exe -e -k 12345678901234567890123456789012 -p E:\testDir
    -> This will encrypt the files directly inside the directory specified
  File_CNG.exe -d -k 12345678901234567890123456789012 -p E:\testDir
    -> This will decrypt the files directly inside the directory specified
  File_CNG.exe -e -k 12345678901234567890123456789012 -p E:\testDir -r
    -> This will encrypt the files inside the directory specified and the files inside any of it's subdirectories
  File_CNG.exe -d -k 12345678901234567890123456789012 -p E:\testDir -r
    -> This will decrypt the files inside the directory specified and the files inside any of it's subdirectories
