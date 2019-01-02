#!/usr/bin/env python
# -*- coding: utf-8 -*-
import PE
import argparse

CODE = '''
push 0h
push message
push title
push 0h
call [MessageBoxA]      ; MessageBoxA(0, "message", "title", 0);

push 0h
call [ExitProcess]      ; exit(0);

message:
db 'message', 0h
title:
db 'title', 0h
'''

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write a minimal PE file which displays a hello box')
    parser.add_argument('-o', type=argparse.FileType('wb'), dest='outputfile', required=True)
    args = parser.parse_args()

    minimalpe = PE.parse()
    minimalpe.addImportSection(['user32.dll:MessageBoxA', 'kernel32.dll:ExitProcess',])
    minimalpe.addCodeSection(CODE)
    minimalpe.writePE(args.outputfile)
