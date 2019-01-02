#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ctypes import *

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

class callbackdata(Structure):
	_fields_=[
		('PID', c_uint32),
		('CALBACKADDR', c_uint32),
	]

class IMAGE_DOS_HEADER(Structure):
	_fields_=[
		('e_magic', c_uint16),
		('e_cblp', c_uint16),
		('e_cp', c_uint16),
		('e_crlc', c_uint16),
		('e_cparhdr', c_uint16),
		('e_minalloc', c_uint16),
		('e_maxalloc', c_uint16),
		('e_ss', c_uint16),
		('e_sp', c_uint16),
		('e_csum', c_uint16),
		('e_ip', c_uint16),
		('e_cs', c_uint16),
		('e_lfarlc', c_uint16),
		('e_ovno', c_uint16),
		('e_res', 4*c_uint16),
		('e_oemid', c_uint16),
		('e_oeminfo', c_uint16),
		('e_res2', 10*c_uint16),
		('e_lfanew', c_uint32),
	]

class IMAGE_FILE_HEADER(Structure):
	_fields_=[
		('Machine', c_uint16),
		('NumberOfSections', c_uint16),
		('TimeDateStamp', c_uint32),
		('PointerToSymbolTable', c_uint32),
		('NumberOfSymbols', c_uint32),
		('SizeOfOptionalHeader', c_uint16),
		('Characteristics', c_uint16),
	]
class IMAGE_DATA_DIRECTORY(Structure):
	_fields_=[
		('VirtualAddress', c_uint32),
		('Size', c_uint32),
	]
class IMAGE_OPTIONAL_HEADER32(Structure):
	_fields_=[
		('Magic', c_uint16),
		('MajorLinkerVersion', c_byte),
		('MinorLinkerVersion', c_byte),
		('SizeOfCode', c_uint32),
		('SizeOfInitializedData', c_uint32),
		('SizeOfUninitializedData', c_uint32),
		('AddressOfEntryPoint', c_uint32),
		('BaseOfCode', c_uint32),
		('BaseOfData', c_uint32),
		('ImageBase', c_uint32),
		('SectionAlignment', c_uint32),
		('FileAlignment', c_uint32),
		('MajorOperatingSystemVersion', c_uint16),
		('MinorOperatingSystemVersion', c_uint16),
		('MajorImageVersion', c_uint16),
		('MinorImageVersion', c_uint16),
		('MajorSubsystemVersion', c_uint16),
		('MinorSubsystemVersion', c_uint16),
		('Win32VersionValue', c_uint32),
		('SizeOfImage', c_uint32),
		('SizeOfHeaders', c_uint32),
		('CheckSum', c_uint32),
		('Subsystem', c_uint16),
		('DllCharacteristics', c_uint16),
		('SizeOfStackReserve', c_uint32),
		('SizeOfStackCommit', c_uint32),
		('SizeOfHeapReserve', c_uint32),
		('SizeOfHeapCommit', c_uint32),
		('LoaderFlags', c_uint32),
		('NumberOfRvaAndSizes', c_uint32),
		('DataDirectory', IMAGE_DATA_DIRECTORY*IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
	]
class IMAGE_OPTIONAL_HEADER64(Structure):
	_fields_=[
		('Magic', c_uint16),
		('MajorLinkerVersion', c_byte),
		('MinorLinkerVersion', c_byte),
		('SizeOfCode', c_uint32),
		('SizeOfInitializedData', c_uint32),
		('SizeOfUninitializedData', c_uint32),
		('AddressOfEntryPoint', c_uint32),
		('BaseOfCode', c_uint32),
		('ImageBase', c_uint64),
		('SectionAlignment', c_uint32),
		('FileAlignment', c_uint32),
		('MajorOperatingSystemVersion', c_uint16),
		('MinorOperatingSystemVersion', c_uint16),
		('MajorImageVersion', c_uint16),
		('MinorImageVersion', c_uint16),
		('MajorSubsystemVersion', c_uint16),
		('MinorSubsystemVersion', c_uint16),
		('Win32VersionValue', c_uint32),
		('SizeOfImage', c_uint32),
		('SizeOfHeaders', c_uint32),
		('CheckSum', c_uint32),
		('Subsystem', c_uint16),
		('DllCharacteristics', c_uint16),
		('SizeOfStackReserve', c_uint64),
		('SizeOfStackCommit', c_uint64),
		('SizeOfHeapReserve', c_uint64),
		('SizeOfHeapCommit', c_uint64),
		('LoaderFlags', c_uint32),
		('NumberOfRvaAndSizes', c_uint32),
		('DataDirectory', IMAGE_DATA_DIRECTORY*IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
	]
class IMAGE_NT_HEADERS32(Structure):
	_fields_=[
		('Signature', c_uint32),
		('FileHeader', IMAGE_FILE_HEADER),
		('OptionalHeader', IMAGE_OPTIONAL_HEADER32),
	]
class IMAGE_NT_HEADERS64(Structure):
	_fields_=[
		('Signature', c_uint32),
		('FileHeader', IMAGE_FILE_HEADER),
		('OptionalHeader', IMAGE_OPTIONAL_HEADER64),
	]
class Misc(Union):
	_fields_=[
		('PhysicalAddress', c_uint32),
		('VirtualSize', c_uint32),
	]
class IMAGE_SECTION_HEADER(Structure):
	_fields_=[
		('Name', 8*c_byte),
		('Misc', Misc),
		('VirtualAddress', c_uint32),
		('SizeOfRawData', c_uint32),
		('PointerToRawData', c_uint32),
		('PointerToRelocations', c_uint32),
		('PointerToLinenumbers', c_uint32),
		('NumberOfRelocations', c_uint16),
		('NumberOfLinenumbers', c_uint16),
		('Characteristics', c_uint32),
	]
class IMAGE_IMPORT_DESCRIPTOR(Structure):
	_fields_=[
		('OriginalFirstThunk', c_uint32),
		('TimeDateStamp', c_uint32),
		('ForwarderChain', c_uint32),
		('Name', c_uint32),
		('FirstThunk', c_uint32),
	]

class u1(Union):
	_fields_=[
		('Function', c_uint32),
		('Ordinal', c_uint32),
		('AddressOfData', c_uint32),
		('ForwarderStringl', c_uint32),
		('ForwarderString', c_uint32),
	]
class IMAGE_THUNK_DATA(Structure):
	_fields_=[
		('u1', u1),
	]

class IMAGE_IMPORT_BY_NAME(Structure):
	_fields_=[
		('Hint', c_uint32),
		('Name', c_char_p),
	]
class PROCESS_INFORMATION(Structure):
	_fields_=[
		('Process', c_uint32),
		('Thread', c_uint32),
		('ProcessId', c_uint32),
		('ThreadId', c_uint32),
	]
class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_=[
        ('Characteristics', c_uint32),
        ('TimeDateStamp', c_uint32),
        ('MajorVersion', c_uint16),
        ('MinorVersion', c_uint16),
        ('Name', c_uint32),
        ('Base', c_uint32),
        ('NumberOfFunctions', c_uint32),
        ('NumberOfNames', c_uint32),
        ('AddressOfFunctions', c_uint32),
        ('AddressOfNames', c_uint32),
        ('AddressOfNameOrdinals', c_uint32),
    ]
class THREADENTRY32(Structure):
    _fields_=[
        ('dwSize', c_uint32),
        ('cntUsage', c_uint32),
        ('th32ThreadID', c_uint32),
        ('th32OwnerProcessID', c_uint32),
        ('tpBasePri', c_uint32),
        ('tpDeltaPri', c_uint32),
        ('dwFlags', c_uint32),
	]
class STARTUPINFO(Structure):
	_fields_=[
		('cb', c_uint32),
		('Reserved', c_void_p),
		('Desktop', c_void_p),
		('Title', c_void_p),
		('X', c_uint32),
		('Y', c_uint32),
		('XSize', c_uint32),
		('YSize', c_uint32),
		('XCountChars', c_uint32),
		('YCountChars', c_uint32),
		('FillAttribute', c_uint32),
		('Flags', c_uint32),
		('ShowWindow', c_uint16),
		('cbReserved2', c_uint16),
		('Reserved2', c_void_p),
		('StdInput', c_uint32),
		('StdOutput', c_uint32),
		('StdError', c_uint32),
	]
#FIXME: clean
class CONTEXT(Structure):
	_fields_=[
		('ContextFlags', c_uint32),
		('Dr0', c_uint32),
		('Dr1', c_uint32),
		('Dr2', c_uint32),
		('Dr3', c_uint32),
		('Dr6', c_uint32),
		('Dr7', c_uint32),
		('FloatSave', c_byte*0x70),
		('SegGs', c_uint32),
		('SegFs', c_uint32),
		('SegEs', c_uint32),
		('SegDs', c_uint32),
		('Edi', c_uint32),
		('Esi', c_uint32),
		('Ebx', c_uint32),
		('Edx', c_uint32),
		('Ecx', c_uint32),
		('Eax', c_uint32),
		('Ebp', c_uint32),
		('Eip', c_uint32),
		('SegCs', c_uint32),
		('EFlags', c_uint32),
		('Esp', c_uint32),
		('SegSs', c_uint32),
		('ExtendedRegisters', c_byte*512),
	]
class LdrLoadDllArg(Structure):
	_fields_=[
		('PathToFile', c_void_p),
		('Flags', c_uint32),
		('ModuleFileName', c_void_p),
		('ModuleHandle', c_void_p),
	]
MAX_PATH=255
MAX_MODULE_NAME32=255
class tagMODULEENTRY32(Structure):
	_fields_=[
  		('dwSize', c_uint32),
  		('th32ModuleID', c_uint32),
  		('th32ProcessID', c_uint32),
  		('GlblcntUsage', c_uint32),
  		('ProccntUsage', c_uint32),
  		('modBaseAddr', c_void_p),
  		('modBaseSize', c_uint32),
  		('hModule', c_void_p),
  		('szModule', MAX_PATH*c_byte),
  		('szExePath', MAX_PATH*c_byte),
  		('dwFlags',  c_uint32),
	]
class MODULEINFO(Structure):
	_fields_=[
		('BaseOfDll', c_void_p),
		('SizeOfImage', c_uint32),
		('EntryPoint', c_void_p),
	]
class PROCESS_BASIC_INFORMATION(Structure):
	_fields_=[
		('Reserved1', c_void_p),
   		('PebBaseAddress', c_void_p),
   		('Reserved2', c_void_p*2),
   		('UniqueProcessId', c_void_p),
   		('Reserved3', c_void_p),
    ]
class PEB(Structure):
	_fields_=[
		('Reserved1', c_byte*2),
		('BeingDebugged', c_byte),
		('Reserved2', c_byte),
		('Reserved3', c_void_p*2),
		('Ldr', c_void_p),
		('ProcessParameters', c_void_p),
		('Reserved4', c_byte*104),
		('Reserved5', c_void_p*52),
		('PostProcessInitRoutine', c_void_p),
		('Reserved6', c_byte*128),
		('Reserved7', c_void_p),
		('SessionId', c_uint32),
	]
class PEB_LDR_DATA(Structure):
	_fields_=[
		('Reserved1', c_byte*8),
		('Reserved2', c_void_p*3),
		('InMemoryOrderModuleList', c_void_p),
	]

class LIST_ENTRY(Structure):
	_fields_=[
		('Flink', c_void_p),
		('Blink', c_void_p),
	]
class LSA_UNICODE_STRING(Structure):
	_fields_=[
		('Length', c_uint16),
		('MaximumLength', c_uint16),
		('Buffer', c_void_p),
  	]
class LDR_DATA_TABLE_ENTRY(Structure):
	_fields_=[
	    ('Reserved1', 2*c_void_p),
	    ('InMemoryOrderLinks', c_void_p),
	    ('Reserved2', c_void_p),
	    ('DllBase', c_void_p),
	    ('EntryPoint', c_void_p),
	    ('Reserved3', c_void_p),
	    ('FullDllName', LSA_UNICODE_STRING),
	    ('Reserved4', c_void_p*8),
	    ('Reserved5', c_void_p*3),
	    ('Reserved6', c_void_p),
	]
class SYSTEM_INFO(Structure):
	_fields_=[
	    ('dwOemId', c_uint32),
	    ('dwPageSize', c_uint32),
	    ('lpMinimumApplicationAddress', c_void_p),
	    ('lpMaximumApplicationAddress', c_void_p),
	    ('dwActiveProcessorMask', c_void_p),
	    ('dwNumberOfProcessors', c_uint32),
	    ('dwProcessorType', c_uint32),
	    ('dwAllocationGranularity', c_uint32),
	    ('wProcessorLevel', c_uint16),
	    ('wProcessorRevision', c_uint16),
	]
class MEMORY_BASIC_INFORMATION(Structure):
	_fields_=[
  	    ('BaseAddress', c_void_p),
  	    ('AllocationBase', c_void_p),
  	    ('AllocationProtect', c_uint32),
  	    ('RegionSize', c_uint32),
  	    ('State', c_uint32),
  	    ('Protect', c_uint32),
  	    ('Type', c_uint32),
	]
class IMAGE_RESOURCE_DIRECTORY(Structure):
	_fields_=[
		('Characteristics', c_uint32),
		('TimeDateStamp', c_uint32),
		('MajorVersion', c_uint16),
		('MinorVersion', c_uint16),
		('NumberOfNamedEntries', c_uint16),
		('NumberOfIdEntries', c_uint16),
	]
class IMAGE_RESOURCE_DIRECTORY_ENTRY(Structure):
	_fields_=[
		('Name', c_uint32),
 		('OffsetToData', c_uint32),
 	]
class IMAGE_RESOURCE_DATA_ENTRY(Structure):
	_fields_=[
		('OffsetToData', c_uint32),
		('Size', c_uint32),
		('CodePage', c_uint32),
		('Reserved', c_uint32),
	]
#WINDOWS FLAGS
ProcessBasicInformation=0
TH32CS_SNAPMODULE32=0x00000010
TH32CS_SNAPMODULE=0x00000008
LIST_MODULES_ALL=0x03
ERROR_PARTIAL_COPY=299
CREATE_SUSPENDED=0X4
MEM_RESERVE=0x00002000
MEM_COMMIT=0x1000
PAGE_EXECUTE=0x10
PAGE_EXECUTE_READ=0x20
PAGE_EXECUTE_READWRITE=0x40
PAGE_READWRITE=0x04
PAGE_READONLY=0x2
PAGE_EXECUTE_WRITECOPY=0x80
INFINITE=-1
PROCESS_ALL_ACCESS=0x1F0FFF
WAIT_FAILED=0xFFFFFFFF
TH32CS_SNAPMODULE=0x00000008
INVALID_HANDLE_VALUE=0xFFFFFFFF
TH32CS_SNAPNOHEAPS=0x40000000
TH32CS_SNAPPROCESS=0x00000002
TH32CS_SNAPTHREAD=0x00000004
PROCESS_ALL_ACCESS=0x1fffff
MEM_DECOMMIT=0x4000
MEM_RELEASE=0x8000
#resource definition
cursor=1
bitmap=2
icon=3
menu=4
dialog=5
string_table=6
font_directory=7
font=8
accelerators=9
unformatted_resource_data=10
message_table=11
group_cursor=12
group_icon=14
version_information=16


stub='''
4d5a90000300000004000000ffff0000b800000000000000400000000000
000000000000000000000000000000000000000000000000000000000000
f00000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d
2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a
240000000000000087451664c3247837c3247837c324783739073837c624
783719076437c8247837c3247837c2247837c32479374424783739076137
ce24783754073d37c224783719076537df24783739074537c22478375269
6368c3247837000000000000000000000000000000000000000000000000
504500004c01000010847d3b0000000000000000e0000f010b0107000000
000000000000000000000000000000000000000000000000000100100000
000200000500010005000100040000000000000000000000000400000000
000002000080000004000010000000001000001000000000000010000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
'''.replace('\n', '').decode('hex')


#windows API definition
'''
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_void_p, c_uint32, c_void_p)
ReadProcessMemory=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'ReadProcessMemory'))
WriteProcessMemory=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'WriteProcessMemory'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_uint32, c_uint32)
OpenProcess=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'OpenProcess'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32, c_void_p, c_void_p, c_uint32, c_void_p)
CreateRemoteThread=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'CreateRemoteThread'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32, c_uint32, c_uint32)
VirtualAllocEx=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'VirtualAllocEx'))
proto=WINFUNCTYPE(c_uint32, c_char_p, c_char_p, c_void_p, c_void_p, c_uint32, c_uint32, c_void_p, c_void_p, c_void_p, c_void_p);
CreateProcess=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'CreateProcessA'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p);
GetExitCodeThread=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetExitCodeThread'))
GetThreadContext=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetThreadContext'))
SetThreadContext=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'SetThreadContext'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_uint32);
WaitForSingleObject=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'WaitForSingleObject'))
proto=WINFUNCTYPE(c_uint32)
GetLastError=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetLastError'))
proto=WINFUNCTYPE(c_uint32, c_uint32)
ResumeThread=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'ResumeThread'))
SuspendThread=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'SuspendThread'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32);
GetProcessImageFileName=proto(windll.kernel32.GetProcAddress(windll.Psapi._handle, 'GetProcessImageFileNameA'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_uint32, c_void_p, c_uint32);
GetModuleFileNameEx=proto(windll.kernel32.GetProcAddress(windll.Psapi._handle, 'GetModuleFileNameExA'))
GetModuleInformation=proto(windll.kernel32.GetProcAddress(windll.Psapi._handle, 'GetModuleInformation'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32,  c_void_p)
EnumProcessModules=proto(windll.kernel32.GetProcAddress(windll.Psapi._handle, 'EnumProcessModules'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32,  c_void_p, c_uint)
EnumProcessModulesEx=proto(windll.kernel32.GetProcAddress(windll.Psapi._handle, 'EnumProcessModulesEX'))
proto=WINFUNCTYPE(c_uint32, c_void_p, c_uint32, c_void_p,  c_void_p)
InitializeContext=proto(windll.kernel32.GetProcAddress(windll.Psapi._handle, 'InitializeContext'))
proto=WINFUNCTYPE(c_uint32, c_uint32)
GetProcessId=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetProcessId'))
GetThreadId=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetThreadId'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p)
GetExitCodeThread=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetExitCodeThread'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32, c_uint32, c_uint32)
VirtualAllocEx=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'VirtualAllocEx'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32, c_void_p, c_void_p, c_uint32,  c_void_p)
CreateRemoteThread=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'CreateRemoteThread'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32, c_uint32, c_void_p)
VirtualProtectEx=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'VirtualProtectEx'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_uint32)
WaitForSingleObject=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'WaitForSingleObject'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p)
GetExitCodeThread=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetExitCodeThread'))
Thread32First=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'Thread32First'))
Thread32Next=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'Thread32Next'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_uint32)
CreateToolhelp32Snapshot=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'CreateToolhelp32Snapshot'))
proto=WINFUNCTYPE(c_uint32, c_uint32)
CloseHandle=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'CloseHandle'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_uint32, c_uint32)
OpenProcess=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'OpenProcess'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p)
AddVectoredExceptionHandler=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'AddVectoredExceptionHandler'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_void_p, c_uint32)
GetModuleBaseName=proto(windll.kernel32.GetProcAddress(windll.Psapi._handle, 'GetModuleBaseName'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_uint32)
CreateToolhelp32Snapshot=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'CreateToolhelp32Snapshot'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p)
Module32First=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'Module32First'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_uint32, c_void_p, c_uint32, c_void_p)
NtQueryInformationProcess=proto(windll.kernel32.GetProcAddress(windll.Ntdll._handle, 'NtQueryInformationProcess'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_uint32)
GetProcessMemoryInfo=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetProcessMemoryInfo'))
proto=WINFUNCTYPE(c_uint32, c_void_p)
GetSystemInfo=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'GetSystemInfo'))
proto=WINFUNCTYPE(c_uint32, c_uint32, c_void_p, c_void_p, c_uint32)
VirtualQueryEx=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'VirtualQueryEx'))
proto=WINFUNCTYPE(c_uint32, c_void_p, c_void_p, c_uint32, c_uint32)
VirtualFreeEx=proto(windll.kernel32.GetProcAddress(windll.kernel32._handle, 'VirtualFreeEx'))
'''

aribitraryimportlist=['KERNEL32.dll:Sleep', 'USER32.dll:GetWindowTextW', 'msvcrt.dll:exit', 'KERNEL32.dll:GetProfileStringW', 'USER32.dll:LoadStringW', 'USER32.dll:SetDlgItemInt', 'USER32.dll:GetSysColor',
'USER32.dll:GetMenu', 'KERNEL32.dll:GlobalSize', 'USER32.dll:TranslateAcceleratorW', 'msvcrt.dll:__p__fmode', 'KERNEL32.dll:GetModuleHandleA', 'USER32.dll:DispatchMessageW', 'USER32.dll:GetWindowRect',
'msvcrt.dll:wcschr', 'USER32.dll:SendMessageW', 'KERNEL32.dll:WriteProfileStringW', 'KERNEL32.dll:LoadLibraryA', 'KERNEL32.dll:LocalReAlloc', 'msvcrt.dll:__p__commode', 'KERNEL32.dll:CreateThread',
'USER32.dll:SetWindowPos', 'USER32.dll:CheckRadioButton', 'USER32.dll:SetWindowTextW', 'USER32.dll:TranslateMessage', 'USER32.dll:ShowWindow', 'msvcrt.dll:_wcsrev', 'KERNEL32.dll:lstrcmpW',
'USER32.dll:CallWindowProcW', 'msvcrt.dll:_exit', 'KERNEL32.dll:SetEvent', 'USER32.dll:SetFocus', 'USER32.dll:GetSubMenu', 'USER32.dll:GetDesktopWindow',
'msvcrt.dll:__CxxFrameHandler', 'USER32.dll:CharNextW', 'USER32.dll:InvalidateRect', 'msvcrt.dll:_CxxThrowException', 'USER32.dll:DialogBoxParamW', 'msvcrt.dll:_cexit',
'USER32.dll:GetDlgItem', 'USER32.dll:EndDialog', 'USER32.dll:CharNextA', 'msvcrt.dll:_controlfp', 'USER32.dll:ChildWindowFromPoint', 'USER32.dll:DestroyMenu', 'USER32.dll:GetMessageW',
'msvcrt.dll:__set_app_type', 'msvcrt.dll:_acmdln', 'msvcrt.dll:wcstoul', 'USER32.dll:IsClipboardFormatAvailable', 'USER32.dll:GetClientRect', 'USER32.dll:MapWindowPoints',
'GDI32.dll:SetBkMode', 'KERNEL32.dll:lstrcatW', 'USER32.dll:TrackPopupMenuEx', 'KERNEL32.dll:GetProfileIntW', 'msvcrt.dll:_XcptFilter', 'msvcrt.dll:_initterm', 'KERNEL32.dll:GlobalCompact',
'KERNEL32.dll:WaitForSingleObject', 'GDI32.dll:SetTextColor', 'msvcrt.dll:wcslen', 'USER32.dll:LoadAcceleratorsW', 'USER32.dll:GetWindowLongW', 'USER32.dll:OpenClipboard', 'ADVAPI32.dll:RegQueryValueExA',
'USER32.dll:UpdateWindow', 'KERNEL32.dll:GlobalLock', 'msvcrt.dll:memmove', 'msvcrt.dll:_except_handler3', 'ADVAPI32.dll:RegOpenKeyExA', 'USER32.dll:GetProcessDefaultLayout', 'USER32.dll:SetWindowLongW',
'USER32.dll:RegisterClassExW', 'msvcrt.dll:_adjust_fdiv', 'USER32.dll:OffsetRect', 'USER32.dll:LoadCursorW', 'USER32.dll:HideCaret', 'KERNEL32.dll:GetProcAddress', 'USER32.dll:CheckMenuRadioItem',
'msvcrt.dll:??1type_info@@UAE@XZ', 'USER32.dll:DrawTextW', 'KERNEL32.dll:GlobalAlloc', 'KERNEL32.dll:LocalFree', 'USER32.dll:EnableMenuItem', 'USER32.dll:DefWindowProcW', 'USER32.dll:MessageBoxW', 'USER32.dll:MessageBoxA',
'USER32.dll:GetClipboardData', 'KERNEL32.dll:GlobalUnlock', 'USER32.dll:MessageBeep', 'KERNEL32.dll:GlobalFree', 'msvcrt.dll:?terminate@@YAXXZ',
'msvcrt.dll:??3@YAXPAX@Z', 'KERNEL32.dll:lstrcpyW', 'KERNEL32.dll:lstrcpynW', 'ADVAPI32.dll:RegCloseKey', 'USER32.dll:SetCursor', 'msvcrt.dll:__getmainargs', 'USER32.dll:EnableWindow',
'KERNEL32.dll:GetStartupInfoA', 'KERNEL32.dll:CreateEventW', 'KERNEL32.dll:GetProcAddress', 'msvcrt.dll:toupper', 'USER32.dll:SetMenu', 'KERNEL32.dll:LocalAlloc', 'KERNEL32.dll:GetCommandLineW', 'KERNEL32.dll:lstrlenW',
'KERNEL32.dll:CloseHandle', 'KERNEL32.dll:ResetEvent', 'USER32.dll:GetDlgCtrlID', 'USER32.dll:IsDialogMessageW', 'USER32.dll:DestroyWindow', 'USER32.dll:SetDlgItemTextW', 'USER32.dll:CreateDialogParamW',
'USER32.dll:LoadMenuW', 'USER32.dll:SystemParametersInfoW', 'USER32.dll:CreateWindowExW', 'USER32.dll:WinHelpW', 'USER32.dll:LoadIconW', 'USER32.dll:ScreenToClient', 'msvcrt.dll:__setusermatherr',
'USER32.dll:IsChild', 'USER32.dll:GetSysColorBrush', 'USER32.dll:CheckMenuItem', 'USER32.dll:CheckDlgButton', 'msvcrt:_onexit', 'msvcrt:atexit', 'msvcrt.dll:_c_exit', 'USER32.dll:CloseClipboard', 'USER32.dll:PostQuitMessage',
'USER32.dll:SetProcessDefaultLayout', 'GDI32.dll:SetBkColor', 'KERNEL32.dll:GlobalReAlloc']
