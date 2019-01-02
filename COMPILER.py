#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, shlex, subprocess
from tempfile import *

def LoadDLL32(dllname, process):
	return compile('''
	[BITS 32]
	LoadLibraryA	equ		''' + hex(int(process.getIAT("kernel32.dll", "LoadLibraryA"))) + '''
	entrypoint:
		call string_offset
		db \'''' + dllname.replace('\n', '') + '''\', 0h
	string_offset:
		mov eax, LoadLibraryA
		call eax
	ret
	''')

def decompile(binarycode):
	binaryfile = NamedTemporaryFile(delete=False)
	binaryfile.write(binarycode)
	binaryfile.close()
	process = subprocess.Popen(['ndisasm', '-b32', binaryfile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	process.wait()
	os.unlink(binaryfile.name)
	return process.stdout.read()

def splitcode(binarycode, offset):
	data=decompile(binarycode)
	for line in data.split('\n'):
		try:
			lineoffset=int(line.split()[0], 16)
			if lineoffset >= offset:
				return binarycode[:lineoffset]
		except:pass
	return None
def compile(sourcecode):
	sourcefile = NamedTemporaryFile(delete=False)
	sourcefile.write(sourcecode)
	sourcefile.close()
	binaryfile=mktemp()
	process=subprocess.Popen(['nasm', '-fbin', '-o', binaryfile, sourcefile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	process.wait()
	os.unlink(sourcefile.name)
	if not os.path.exists( binaryfile ):
		print process.stdout.read()
		print process.stderr.read()
		raise Exception('Problem during code compilation')

	data=open(binaryfile, 'rb').read()
	if len(data) == 0:
		raise Exception('Problem during code compilation')
	return data
