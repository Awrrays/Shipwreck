
# -*- coding: utf-8 -*-
# @Date    : 2021-10-12 12:55:28
# @Author  : Your Name (you@example.org)
# @Link    : http://example.org
# @Version : $Id$


from Lib.Encrypt import Encrypt

from Lib.psObf import allObf

from Lib.common import cmdLineParser
from Lib.common import writeFile
from Lib.common import echo

from Lib.compile import syscall
from Lib.compile import alloc
from Lib.compile import GetTemplateContent
from Lib.compile import EncryptCompileTrim

from Lib.unCompile import toPs1
from Lib.unCompile import bitJudge
from Lib.unCompile import EncryptunCompileTrim


if __name__ == '__main__':

	args = cmdLineParser()

	binFile = args.filename
	is_syscall = args.syscall
	EncryptType = args.encryptType
	AllocMethod = args.alloc
	callback = args.callback
	is_64 = args.bit
	scriptType = args.script
	is_obf = args.obf


	e = Encrypt(binFile)

	if EncryptType == 'b64':
		e.base64_encode()
	elif EncryptType == 'xor':
		e.xor()		
	elif EncryptType == 'aes':
		e.aes()
	elif EncryptType == 'uuid':
		e.touuid()
	elif EncryptType == 'mac':
		e.tomac()
	elif EncryptType == 'ipv4':
		e.toipv4()


	if scriptType == 'cpp' or scriptType == 'dll':
		cppContent, lib = GetTemplateContent(callback)	
		cppContent = EncryptCompileTrim(cppContent, EncryptType)

		lib += e.EncryptLib

		cppContent = cppContent.replace('<Ciphertext>', e.CipherText)
		cppContent = cppContent.replace('<decode>', e.cppDecode)

		if is_syscall:
			cppContent = syscall(cppContent)
		else:
			cppContent = cppContent.replace('#include "syscall.h"', '')
		cppContent = alloc(AllocMethod, cppContent)
		Content = cppContent

	else:
		lib = ''
		if EncryptType == 'uuid' or EncryptType == 'mac' or EncryptType == 'ipv4':
			CipherText = e.CipherText[1:-3]
		else:
			CipherText = e.CipherText

		ps1Content = toPs1(CipherText, e.ps1Decode)
		ps1Content = EncryptunCompileTrim(ps1Content, EncryptType)
		Content = bitJudge(ps1Content, is_64)

		if is_obf:
			Content = allObf(Content)


	writeFile(Content, scriptType)

	echo(args, e.CipherText, e.key, lib)