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

namespace ELFLoader
{
bool LoadFile(void* file)
{
	Elf32_Ehdr* header = (Elf32_Ehdr*)file;
	if(!CheckSupported(header)
		return false;
	Elf32_Phdr* prog_hdr = (Elf32_Phdr*)(file + header->e_phoff);
	ParseProgramHeader(prog_hdr);
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
