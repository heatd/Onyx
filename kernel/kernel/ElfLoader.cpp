/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**************************************************************************
 *
 *
 * File: ElfLoader.cpp
 *
 * Description: Elf Loader
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <kernel/ElfLoader.h>
#include <kernel/tty.h>
#include <kernel/mm.h>
#include <kernel/kthread.h>
#include <stdio.h>
namespace ELFLoader
{

extern int errno = 0;
int ParseProgramHeader(Elf32_Phdr* prog_hdr,Elf32_Half entries,void* file)
{
	for(int i = 0; i <= entries; i++)
	{
		if(prog_hdr[i].p_type == 1)
		{
			if(VMM::MarkAddressAsUsed((void*)prog_hdr[i].p_vaddr,prog_hdr[i].p_memsz / 1024) == 1)
			{
				return 1;
			}
			if(prog_hdr[i].p_filesz < prog_hdr[i].p_memsz)
			{
				// Its the bss section, zero it out
				kmmap(prog_hdr[i].p_vaddr,prog_hdr[i].p_memsz / 1024,_PDE_WRITABLE);
				memset((void*)prog_hdr[i].p_vaddr,0,prog_hdr[i].p_memsz);
			}
			kmmap(prog_hdr[i].p_vaddr,prog_hdr[i].p_memsz / 1024 + 1024,_PDE_WRITABLE);
			memcpy((void*)prog_hdr[i].p_vaddr,file + prog_hdr[i].p_offset,prog_hdr[i].p_filesz);
		}
	}
	return 0;
}
bool LoadFile(void* file)
{
	Elf32_Ehdr* header = (Elf32_Ehdr*)file;
	if(!CheckSupported(header))
		return false;
	Elf32_Phdr* prog_hdr = (Elf32_Phdr*)(file + header->e_phoff);
	if(ParseProgramHeader(prog_hdr,header->e_phnum,file) == 1)
	{
		ThrowError(0x4,"Invalid Load address");
		return false;
	}
	KThread* kt = CreateThread((KThread_Entry_point)header->e_entry);
	kt->Start();
}
void ThrowError(int errn,const char* err_msg)
{
	errno = errn;
	TTY::SetColor(0xFF0000);
	printf("[ KERNEL ]( ELF LOADER ) error: %s\n",err_msg);
	TTY::SetColor(0xC0C0C0);
}
bool CheckSupported(Elf32_Ehdr* header)
{
	if(header->e_ident[EI_MAG0] != ELFMAG0)
	{
		ThrowError(HDR_INV,"Invalid ELF header!");
		return false;
	}
	if(header->e_ident[EI_MAG1] != ELFMAG1)
	{
		ThrowError(HDR_INV,"Invalid ELF header!");
		return false;
	}
	if(header->e_ident[EI_MAG2] != ELFMAG2)
	{
		ThrowError(HDR_INV,"Invalid ELF header!");
		return false;
	}
	if(header->e_ident[EI_MAG3] != ELFMAG3)
	{
		ThrowError(HDR_INV,"Invalid ELF header!");
		return false;
	}
	if(header->e_ident[EI_CLASS] != ELFCLASS32)
	{
		ThrowError(ARCH_INV,"Invalid architecture!");
		return false;
	}
	if(header->e_ident[EI_DATA] != ELFDATA2LSB)
	{
		ThrowError(DATAORDER_INV,"Invalid Byte order!");
		return false;
	}
	if(header->e_type != ET_EXEC)
	{
		ThrowError(HDR_INV,"ELF type not loadable by the OS");
		return false;
	}
	return true;
}
}
