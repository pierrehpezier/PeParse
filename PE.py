#!/usr/bin/env python
# -*- coding: utf-8 -*-
from INCLUDE import *
from COMPILER import *
import io, os, array, sys

##
#PE parser and rebuilder class
#
class parse:
	##
	#@brief Convert rva address into raw file address
	#@param value
	# An integer to convert
	#@return
	#RVA value. If the raw adddress is outside the PE, this function will return 0.
	def rvaToRaw(self, value):
		for i in self.IMAGE_SECTION_HEADERS:
			if (value >= i.VirtualAddress) and value <= (i.Misc.VirtualSize+i.VirtualAddress):
				return value - i.VirtualAddress + i.PointerToRawData
		return 0
	##
	#@brief retreive section from RVA
	#@param offset
	#The RVA
	#@return
	#The IMAGE_SECTION_HEADER of the section containing the offset
	def getSectionFromRva(self, offset):
		for section in self.IMAGE_SECTION_HEADERS:
			if (offset >= section.VirtualAddress) and offset <= (section.Misc.VirtualSize+section.VirtualAddress):
				return section
		return None
	##
	#@brief retreive ressource section
	#@return
	#The IMAGE_SECTION_HEADER of the resource section
	def getRessourceSection(self):
		return self.getSectionFromRva(self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[2].VirtualAddress)
	##
	#@brief Convert raw file address into rva address
	#@param value
	#An integer to convert
	#@return
	#RVA value. If the raw file address does not exist, this function will return 0.
	def rawToRva(self, value):
		for section in self.IMAGE_SECTION_HEADERS:
			if (value >= section.PointerToRawData) and value <= (section.SizeOfRawData+section.PointerToRawData):
				return value - section.PointerToRawData + section.VirtualAddress
		return 0
	##
	#@brief Align an integer using SectionAlignment field in OptionalHeader.
	#@param value
	#The Integer to convert
	#@return
	#Converted integer
	def VirtualAlign(self, value):
		if value%self.IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment == 0:
			return value
		return (value/self.IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment+1)*self.IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment
	##
	#@brief Align an integer using FileAlignment field in OptionalHeader.
	#@param value
	#The Integer to convert
	#@return
	#Converted integer
	def RawAlign(self, value):
		if value%self.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment == 0:
			return value
		return (value/self.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment+1)*self.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment
	##
	#@brief retrieve the size of the padding beween PE file header and the first byte of the first section.
	#@return
	#The size of the padding area
	def getSectionPadding(self):
		min_sec_offset=0x100000
		for section in self.IMAGE_SECTION_HEADERS:
			if section.PointerToRawData > 0:
				min_sec_offset=min(section.PointerToRawData, min_sec_offset)
		return min_sec_offset-(self.IMAGE_DOS_HEADER.e_lfanew+sizeof(self.IMAGE_NT_HEADERS)+self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER))
		##
	#@brief Get the offset of shellcode injected by function injectloader
	#@retun
	#The RVA of the offset
	def getLoaderOffset(self):
		section=self.IMAGE_SECTION_HEADERS[self.getCodeSectionOffset()]
		return self.rawToRva(section.SizeOfRawData+section.PointerToRawData-self.getCodePadding())

	def injectCodeLoader(self, sourcecode, rvaoffset=-1):
		#if len( data ) > self.getCodePadding():
		#	#TODO: add section if the padding is too small
		#	raise exception('padding too small: not implemented yet..')
		codesection = self.IMAGE_SECTION_HEADERS[self.getCodeSectionOffset()]
		offset = len(self.sectionData[self.getCodeSectionOffset()]) - self.getCodePadding()
		if rvaoffset == -1:
			rvaoffset = self.rawToRva(codesection.PointerToRawData + offset)
		#self.sectionData[self.getCodeSectionOffset()]=self.sectionData[self.getCodeSectionOffset()][0:offset]+data+self.sectionData[self.getCodeSectionOffset()][offset+len(data):]
		#self.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint=self.rawToRva(codesection.PointerToRawData + offset)
		formattedsourcecode='''
[bits 32]
[org ''' + str(rvaoffset) + ''']
entrypoint equ ''' + str(self.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint) + '''
'''
		for i in self.iatlist:
			formattedsourcecode += i.split(':')[1] + ' equ ' + str(self.iatlist[i] + self.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)+'\n'
		formattedsourcecode += sourcecode
		data = compile(formattedsourcecode)
		self.injectLoader(data)
	##
	#@brief Inject a shellcode at the beginning of the code section
	#The entrypoint will point to it
	#@param data
	#The shellcode
	def injectLoader(self, data):
		if len( data ) > self.getCodePadding():
			#TODO: add section if the padding is too small
			raise exception('padding too small: not implemented yet..')
		print 'inserted: {}/{} bytes'.format(len(data), self.getCodePadding())
		print data.encode('hex')
		codesection=self.IMAGE_SECTION_HEADERS[self.getCodeSectionOffset()]
		offset=len(self.sectionData[self.getCodeSectionOffset()])-self.getCodePadding()
		self.sectionData[self.getCodeSectionOffset()] = self.sectionData[self.getCodeSectionOffset()][0:offset] + data + self.sectionData[self.getCodeSectionOffset()][offset+len(data):]
		self.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint=self.rawToRva(codesection.PointerToRawData+offset)
                print 'entrypoint', hex(self.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
	##
	#@brief get the padding at the end of code section
	#THis is used to inject payload in executable file
	#@return
	#The padding size
	def getCodePadding(self):
		offset=self.getCodeSectionOffset()
		for i in range( len(self.sectionData[offset])-1, -1, -1):
			if self.sectionData[offset][i] != '\x00':
				paddingoffset=i+2
				break
		return (len(self.sectionData[offset])-paddingoffset)
	#depreciated
	def getCodeSectionOffset(self):
		offset=-1
		for i in range(len(self.IMAGE_SECTION_HEADERS)):
			section=self.IMAGE_SECTION_HEADERS[i]
			if self.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint > section.VirtualAddress and self.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint < section.Misc.VirtualSize:
				offset=i
		if offset == -1:
			raise Exception('Executable section not found')
		return offset
	##
	#@brief retrieve the raw size of the PE executable
	#@return
	#The PE raw size
	def getMaxRawAddr(self):
		max_raw=0
		for section in self.IMAGE_SECTION_HEADERS:
			max_raw=max(max_raw, section.PointerToRawData+section.SizeOfRawData)
		if max_raw == 0:
			return self.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment
		return self.RawAlign(max_raw)
	##
	#@brief retrieve the lower virtual address of the PE executable
	#@return
	#The PE virtual size
	def getMinVirtualAddr(self):
		min_virtual=0x100000
		for section in self.IMAGE_SECTION_HEADERS:
			min_virtual=min(min_virtual, section.VirtualAddress)
		return self.VirtualAlign(min_virtual)
	##
	#@brief retrieve the virtual size of the PE executable
	#@return
	#The PE virtual size
	def getMaxVirtualAddr(self):
		max_virtual=0
		for section in self.IMAGE_SECTION_HEADERS:
			max_virtual=max(max_virtual, section.Misc.VirtualSize+section.VirtualAddress)
		if max_virtual == 0:
			return self.IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment
		return self.VirtualAlign(max_virtual)
	##
	#@brief Add a section using the padding area between PE header and the first section
	#@param
	#An IMAGE_SECTION_HEADER
	#@return
	#An update of IMAGE_SECTION_HEADER
	def addpaddingsection(self, section):
		section.VirtualAddress=self.getMaxVirtualAddr()
		#print hex(section.VirtualAddress)
		section.PointerToRawData=self.getMaxRawAddr()
		self.IMAGE_SECTION_HEADERS.append(section)
		return section
	##
	#@brief Enlarge your pagging area between PE header and the first section
	def addSectionOffset(self):
		for i in range(len(self.IMAGE_SECTION_HEADERS)):
			self.IMAGE_SECTION_HEADERS[i].PointerToRawData+=self.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment
	##
	#@brief Add an initialized section into the executable
	#@param data
	#The raw data of this section
	#@param name [optional]
	#The name of the section (default='.data')
	#@param rights [optional]
	#The section flags
	#@return
	#A IMAGE_SECTION_HEADER structure
	def addSection(self, data, name='.data', rights=0xE0500020):
		section=IMAGE_SECTION_HEADER(SizeOfRawData=self.RawAlign(len(data)))
		memmove(byref(section.Name), name, len(name))
		section.Misc.VirtualSize=self.VirtualAlign(len(data))
		section.Characteristics=rights
		data=data+create_string_buffer(section.SizeOfRawData-len(data)).value
		self.sectionData.append(data)
		while self.getSectionPadding() < sizeof(IMAGE_SECTION_HEADER):
			self.addSectionOffset()
		section=self.addpaddingsection(section)
		self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections+=1
		self.IMAGE_NT_HEADERS.OptionalHeader.SizeOfCode+=section.Misc.VirtualSize;
		self.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders=self.RawAlign(self.IMAGE_DOS_HEADER.e_lfanew+sizeof(self.IMAGE_NT_HEADERS)+self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER))
		self.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage=section.Misc.VirtualSize+section.VirtualAddress
		return section
	##
	#@brief Add an uninitialized section
	#@param Length
	#The length of the section
	#@param name [optional]
	#The section name (default='.bss')
	def addEmptySection(self, length=1024, name='.bss'):
		section=IMAGE_SECTION_HEADER(SizeOfRawData=self.RawAlign(length))
		memmove(byref(section.Name), name, len(name))
		section.Misc.VirtualSize=self.VirtualAlign(length)
		section.Characteristics=0xC0600080
		section.SizeOfRawData=0
		data=create_string_buffer(section.SizeOfRawData).value
		self.sectionData.append(data)
		while self.getSectionPadding() < sizeof(IMAGE_SECTION_HEADER):
			self.addSectionOffset()
		section=self.addpaddingsection(section)
		self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections+=1
		self.IMAGE_NT_HEADERS.OptionalHeader.SizeOfCode+=section.Misc.VirtualSize;
		self.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders=self.RawAlign(self.IMAGE_DOS_HEADER.e_lfanew+sizeof(self.IMAGE_NT_HEADERS)+self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER))
		self.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage=section.Misc.VirtualSize+section.VirtualAddress
		return section
	##
	#@brief Set the raw data to a section
	#@param section
	#A IMAGE_SECTION_HEADER structure corrsponding to the section to modify
	#@param data
	#The raw data to set
	def setsectionData(self, section, data):
		offset=-1
		for i in range(len(self.IMAGE_SECTION_HEADERS)):
			if section.PointerToRawData == self.IMAGE_SECTION_HEADERS[i].PointerToRawData:
				offset=i
		if offset == -1:
			raise Exception('Section not found!')
		if len(data) > len(section.SizeOfRawData):
			raise Exception('trying to add too much data in this section')
		self.sectionData[offset]=data
	##
	#@brief Add an executable section
	#@param sourcecode
	#A buffer containing nasm source code. All the imports are automatically added.
	#The code origin is automatically added
	#@return
	#A IMAGE_SECTION_HEADER	corresponding to the code data
	def addCodeSection(self, sourcecode, name='.text', setentrypoint=True):
		formattedsourcecode='''
[bits 32]
[org '''+str(int(self.getMaxVirtualAddr()+self.IMAGE_NT_HEADERS.OptionalHeader.ImageBase))+''']
'''
		for i in self.iatlist:
			formattedsourcecode += i.split(':')[1] + ' equ ' + str(self.iatlist[i]+self.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)+'\n'
		formattedsourcecode += sourcecode
		data = compile(formattedsourcecode)
		section = self.addSection(data, name, rights=0x60500060)
		if setentrypoint:
			self.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint=section.VirtualAddress
		return section

	##
	#@brief Write PE file To descriptor
	#@param descriptorobj Output pipe
	def writePE(self, descriptorobj=sys.stdout):
		descriptorobj.write(self.rebuidPE())
	##
	#@brief Rebuild the PE file
	#@return
	#A buffer containing PE file raw data
	def rebuidPE(self):
		FILE=io.BytesIO()
		FILE.write(create_string_buffer(self.getMaxRawAddr()))
		FILE.seek(0)
		FILE.write(self.IMAGE_DOS_HEADER)
		FILE.write(create_string_buffer(self.IMAGE_DOS_HEADER.e_lfanew-sizeof(IMAGE_DOS_HEADER)))
		self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[11].VirtualAddress=0
		self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[11].Size=0
		FILE.write(self.IMAGE_NT_HEADERS)
		for section in self.IMAGE_SECTION_HEADERS:
			FILE.write(section)
		for section in self.IMAGE_SECTION_HEADERS:
			FILE.write(section)
		for i in range(self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections):
			if self.IMAGE_SECTION_HEADERS[i].PointerToRawData > 0:
				FILE.seek(self.IMAGE_SECTION_HEADERS[i].PointerToRawData)
				FILE.write(self.sectionData[i])
		data=FILE.getvalue()
		FILE.close()
		return data
	##
	#@brief create imports from scratch
	#@param importlist
	#A list of imports formatted like this: ['KERNEL32.dll:Sleep', 'USER32.dll:GetWindowTextW']
	def addImportSection(self, importlist, name='.idata'):
		FILE=io.BytesIO()
		#parse the library list
		totalimport=0
		libdict={}
		self.iatlist={}
		for i in importlist:
			lib, func=i.strip().split(':')
			if not lib in libdict.keys():libdict[lib]=[]
			libdict[lib].append(func)
			totalimport+=1
		virtaddr=self.getMaxVirtualAddr()
		thunkoffset=sizeof(IMAGE_IMPORT_DESCRIPTOR)*(len(libdict.keys())+1)
		IAToffset=sizeof(IMAGE_THUNK_DATA)*(len(libdict[lib])+totalimport) * 2
		stringoffset = IAToffset + 4 * (totalimport + len(libdict.keys()))
                stringoffset = max(stringoffset, 90)
		descriptoroffset=0
		thunk=IMAGE_THUNK_DATA()
		descriptor=IMAGE_IMPORT_DESCRIPTOR()
		for lib in libdict.keys():
			FILE.seek(descriptoroffset)
			descriptor.Name=virtaddr+stringoffset
			descriptor.OriginalFirstThunk=thunkoffset+virtaddr
			descriptor.FirstThunk=thunkoffset+sizeof(IMAGE_THUNK_DATA)*(len(libdict[lib])+1)+virtaddr
			FILE.write(descriptor)
			FILE.seek(stringoffset)
			FILE.write(lib)
			stringoffset+=len(lib)+1
			descriptoroffset+=sizeof(IMAGE_IMPORT_DESCRIPTOR)
			for func in libdict[lib]:
				FILE.seek(thunkoffset)
				thunk.u1.ForwarderString=virtaddr+stringoffset
				FILE.write(thunk)
				thunkoffset+=sizeof(IMAGE_THUNK_DATA)
				FILE.seek(stringoffset)
				FILE.write('\x00\x00'+func)
				stringoffset+=len(func)+3
				FILE.seek(thunkoffset+sizeof(IMAGE_THUNK_DATA)*(len(libdict[lib])))
				thunk.u1.ForwarderString=IAToffset+virtaddr
				#self.iatlist[lib+':'+func]=int(thunk.u1.ForwarderString)
				self.iatlist[lib+':'+func]=FILE.tell()+virtaddr#+self.IMAGE_NT_HEADERS.OptionalHeader.ImageBase
				FILE.write(thunk)
				IAToffset+=4
			thunkoffset=thunkoffset+4+sizeof(IMAGE_THUNK_DATA)*(len(libdict[lib])+1)
			IAToffset+=4
		section=self.addSection(data=FILE.getvalue(), name=name, rights=0xC0300040)
		FILE.close()
		self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[1].VirtualAddress=section.VirtualAddress
		self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[1].Size=totalimport
	def stringsatOffset(self, FILE, offset):
		origoffset=FILE.tell()
		FILE.seek(offset)
		stringsize=c_uint16()
		FILE.readinto(stringsize)
		retval=c_char_p(FILE.read(2*stringsize.value).replace('\x00', '')).value
		FILE.seek(origoffset)
		return retval
	def createResource(self, resource):
		#count name section
		#for i in resource:
		#	print i[:-1]
		objects=list(set(i[0] for i in resource))

		entry=IMAGE_RESOURCE_DIRECTORY_ENTRY()
		root=IMAGE_RESOURCE_DIRECTORY()
		leaf=IMAGE_RESOURCE_DATA_ENTRY()
		root.MajorVersion=4
		FILE=io.BytesIO()



		#Set ROOT
		rootdict=[]
		for i in resource:rootdict.append(i[0])
		rootdict=list(set(rootdict))
		for i in rootdict:
			if i.__class__.__name__ == 'int':root.NumberOfIdEntries+=1
			else:root.NumberOfNamedEntries+=1
		FILE.write(root)
		#WAVE 1
		for i in range(len(rootdict)):
			entry.Name=rootdict[i]
			entry.OffsetToData=sizeof(IMAGE_RESOURCE_DIRECTORY)+len(rootdict)*sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)+0x80000000
			for k in range(i):
				entry.OffsetToData+=sizeof(IMAGE_RESOURCE_DIRECTORY)
				for l in resource:
					if l[0] == rootdict[k]:
						entry.OffsetToData+=sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)
			#print hex(entry.OffsetToData)
			FILE.write(entry)
		#WAVE2
		prout={}
		wave3list=[]
		wave3offset=0
		for i in rootdict:
			root.NumberOfNamedEntries=0
			root.NumberOfIdEntries=0
			for j in resource:
				if j[0] == i:
					if j[1].__class__.__name__ == 'int':root.NumberOfIdEntries+=1
					else:root.NumberOfNamedEntries+=1
			prout[i]=root.NumberOfNamedEntries+root.NumberOfIdEntries
			FILE.write(root)
			entry.OffsetToData=0x80000000+FILE.tell()+sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)*len(resource)+sizeof(IMAGE_RESOURCE_DIRECTORY)*len(rootdict)
			if wave3offset == 0:wave3offset=entry.OffsetToData-0x80000000
			entry.Name=74747
			for j in resource:
				if j[0] == i:
					if j[1].__class__.__name__ == 'int':
						entry.Name=j[1]
					else:
						entry.Name=0x999
					print hex(entry.OffsetToData)
					FILE.write(entry)
					entry.OffsetToData+=sizeof(IMAGE_RESOURCE_DIRECTORY)+sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)
					wave3list.append(j)
		#WAVE 3
		print prout
		FILE.seek(wave3offset)
		root.NumberOfIdEntries=1
		root.NumberOfNamedEntries=0
		for i in wave3list:
			entry.Name=i[2]
			entry.OffsetToData=0
			FILE.write(root)
			FILE.write(entry)

		#print hex(FILE.tell())
		for j in range(root.NumberOfIdEntries):
			FILE.write(entry)
		for j in range(root.NumberOfNamedEntries):
			FILE.write(entry)
		'''for imp in rootdict:
			if imp[0].__class__.__name__ == 'int':root.NumberOfIdEntries+=1
			else:root.NumberOfNamedEntries+=1
		'''
		section=self.addSection(FILE.getvalue(), name='.rsrc', rights=0x40000040)
		self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[2].VirtualAddress=section.VirtualAddress
		self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[2].Size=100
		#TODO
		FILE.close()
	##
	#@brief
	#@return
	#
	def parseResource(self):
		FILE=io.BytesIO(self.getSectionData(self.getRessourceSection()))
		sectionoffset=self.getRessourceSection().VirtualAddress
		entry=IMAGE_RESOURCE_DIRECTORY_ENTRY()
		root=IMAGE_RESOURCE_DIRECTORY()
		leaf=IMAGE_RESOURCE_DATA_ENTRY()
		FILE.readinto(root)
		parsedresource=[]
		entrydict={}
		if root.NumberOfNamedEntries > 0:
			raise exception('Named entries: not implemented yet..')
		#wave 1
		for i in range(root.NumberOfIdEntries):
			FILE.readinto(entry)
			entrydict[int(entry.Name)]=entry.OffsetToData
		for i in range(root.NumberOfNamedEntries):
			FILE.readinto(entry)
			NAME=self.stringsatOffset(FILE, entry.Name-0x80000000)
			entrydict[NAME]=entry.OffsetToData
		#print entrydict
		#print
		#wave 2
		for ID in entrydict:
			wave2dict={}
			FILE.seek(entrydict[ID]-0x80000000)
			FILE.readinto(root)
			for i in range(root.NumberOfIdEntries):
				FILE.readinto(entry)
				wave2dict[int(entry.Name)]=entry.OffsetToData
			for i in range(root.NumberOfNamedEntries):
				FILE.readinto(entry)
				wave2dict[self.stringsatOffset(FILE, entry.Name-0x80000000)]=entry.OffsetToData
			#print wave2dict
			entrydict[ID]=wave2dict
		#print entrydict
		#print
		#FUCKING WAVE 3!!!
		for i in entrydict:
			for j in entrydict[i]:
				wave3dict={}
				#print i, j, hex(entrydict[i][j])
				FILE.seek(int(entrydict[i][j])-0x80000000)
				FILE.readinto(root)
				for k in range(root.NumberOfIdEntries):
					FILE.readinto(entry)
					wave3dict[entry.Name]=entry.OffsetToData
				for k in range(root.NumberOfNamedEntries):
					FILE.readinto(entry)
					wave3dict[self.stringsatOffset(FILE, entry.Name-0x80000000)]=entry.OffsetToData
				for k in wave3dict:
					FILE.seek(wave3dict[k])
					FILE.readinto(leaf)
					#print i, j, k, leaf.OffsetToData, leaf.Size
					FILE.seek(leaf.OffsetToData-sectionoffset)
					data=FILE.read(leaf.Size)
					parsedresource.append([i, j, k, data])
		#data=FILE.getvalue()
		FILE.close()
		return parsedresource
	##
	#@brief Returns the raw data of the section passed in parameter
	#@param section
	#An IMAGE_SECTION_HEADER structure
	#@return
	#Raw data
	def getSectionData(self, section):
		return self.sectionData[self.IMAGE_SECTION_HEADERS.index(section)]
	##
	#@brief PE constructor. You must open a pre existing PE.
	#To create a PE from scratch, open the
	#@param data
	#The PE data
	#@param memory
	#Set to True if you want to parse a raw file
	#Set to False if you want to parse a memory buffer (use virtual address instead of raw ones)
	def __init__(self, data=stub, memory=False):
		self.IMAGE_DOS_HEADER=IMAGE_DOS_HEADER()
		self.IMAGE_EXPORT_DIRECTORY=IMAGE_EXPORT_DIRECTORY()
		self.IMAGE_SECTION_HEADERS=[]
		self.raw_size=len(data)
		self.sectionData=[]
		self.iatlist={}
		self.exportlist={}
		self.arch=0
		if len(data) < sizeof(IMAGE_DOS_HEADER):
			raise Exception('Not a DOS executable')
		FILE=io.BytesIO(data)
		FILE.readinto(self.IMAGE_DOS_HEADER)
		self.IMAGE_NT_HEADERS=IMAGE_NT_HEADERS32()
		if self.IMAGE_DOS_HEADER.e_magic != 0x5a4d:
			raise Exception('Not a MZ executable')
		if self.IMAGE_DOS_HEADER.e_lfanew <= sizeof(IMAGE_DOS_HEADER):
			raise Exception('MZ file corrupted')
		FILE.seek(self.IMAGE_DOS_HEADER.e_lfanew)
		FILE.readinto(self.IMAGE_NT_HEADERS)
		if self.IMAGE_NT_HEADERS.Signature != 0x4550:
			raise Exception('Not a PE executable')
		if self.IMAGE_NT_HEADERS.OptionalHeader.Magic == 0x10B:
			self.arch=32
		elif self.IMAGE_NT_HEADERS.OptionalHeader.Magic == 0x20B:
			del(self.IMAGE_NT_HEADERS)
			self.IMAGE_NT_HEADERS=IMAGE_NT_HEADERS64()
			FILE.seek(self.IMAGE_DOS_HEADER.e_lfanew)
			FILE.readinto(self.IMAGE_NT_HEADERS)
			self.arch=64
		else:
			raise Exception('Not a 32/64 Bits executable')
		for i in range(self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections):
			section=IMAGE_SECTION_HEADER()
			FILE.readinto(section)
			self.IMAGE_SECTION_HEADERS.append(section)
			if not memory:
				self.sectionData.append(data[section.PointerToRawData:section.PointerToRawData+section.SizeOfRawData])
			else:
				self.sectionData.append(data[section.VirtualAddress:section.VirtualAddress+section.Misc.VirtualSize])
		if not memory:
			#ADD IAT
			if self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[1].VirtualAddress > 0:
				FILE.seek(self.rvaToRaw(self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[1].VirtualAddress))
				descriptor=IMAGE_IMPORT_DESCRIPTOR()
				#imageimportbyname=IMAGE_IMPORT_BY_NAME()
				thunk1=IMAGE_THUNK_DATA()
				thunk2=IMAGE_THUNK_DATA()
				while True:
					FILE.readinto(descriptor)
					#print descriptor.Name
					if descriptor.Name == 0:
						break
					offset=0
					while True:
						memmove(byref(thunk1), data[self.rvaToRaw(descriptor.OriginalFirstThunk+offset):], sizeof(IMAGE_THUNK_DATA))
						memmove(byref(thunk2), data[self.rvaToRaw(descriptor.FirstThunk+offset):], sizeof(IMAGE_THUNK_DATA))
						if thunk1.u1.ForwarderString==0 or thunk2.u1.ForwarderString==0:
							break
						#print c_char_p(data[self.rvaToRaw(thunk1.u1.ForwarderString)+2:]).value
						#print hex(thunk2.u1.ForwarderString)
						#print hex(self.rawToRva(descriptor.FirstThunk+offset))
						#print hex(descriptor.FirstThunk+offset)
						#print c_char_p(data[self.rvaToRaw(thunk1.u1.ForwarderString)+2:])
						self.iatlist[c_char_p( data[self.rvaToRaw(descriptor.Name):] ).value+':'+c_char_p(data[self.rvaToRaw(thunk1.u1.ForwarderString)+2:]).value]=int(descriptor.FirstThunk+offset)
						#print self.iatlist
						offset+=sizeof(IMAGE_THUNK_DATA)
				FILE.close()
			#TODO
		else:
			FILE.seek(self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[1].VirtualAddress)
			descriptor=IMAGE_IMPORT_DESCRIPTOR()
			thunk1=IMAGE_THUNK_DATA()
			thunk2=IMAGE_THUNK_DATA()
			while True:
				FILE.readinto(descriptor)
				if descriptor.Name == 0:
					break
				offset=0
				while True:
					memmove(byref(thunk1), data[descriptor.OriginalFirstThunk+offset:], sizeof(IMAGE_THUNK_DATA))
					memmove(byref(thunk2), data[descriptor.FirstThunk+offset:], sizeof(IMAGE_THUNK_DATA))
					if thunk1.u1.ForwarderString==0 or thunk2.u1.ForwarderString==0:
						break
					self.iatlist[c_char_p( data[descriptor.Name:] ).value+':'+c_char_p(data[thunk1.u1.ForwarderString+2:]).value]=int(descriptor.FirstThunk+offset)
					offset+=sizeof(IMAGE_THUNK_DATA)
			FILE.seek(self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0].VirtualAddress)
			FILE.readinto(self.IMAGE_EXPORT_DIRECTORY)
			FILE.seek(self.IMAGE_EXPORT_DIRECTORY.AddressOfNames)
			addr=c_uint32()
			funclist=[]
			for i in range(self.IMAGE_EXPORT_DIRECTORY.NumberOfNames):
				FILE.readinto(addr)
				if addr.value == 0:
					break
				funclist.append(c_char_p(data[addr.value:]).value)
			FILE.seek(self.IMAGE_EXPORT_DIRECTORY.AddressOfFunctions)
			for i in range(self.IMAGE_EXPORT_DIRECTORY.NumberOfFunctions):
				addr=c_uint32()
				FILE.readinto(addr)
				try:self.exportlist[funclist[i]]=addr.value
				except:pass
