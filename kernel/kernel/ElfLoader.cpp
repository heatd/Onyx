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

bool ElfCheckFile(Elf32_Ehdr* hdr)
{
	//Return values: true - The file is a valid Elf file
	// false - Invalid Elf file
	if(!hdr)
		return false;
	if(hdr->e_ident[EI_MAG0] != ELFMAG0)
	{
		printf("ELF Header EI_MAG0 incorrect.\n");
		return false;
	}
	if(hdr->e_ident[EI_MAG1] != ELFMAG1)
	{
		printf("ELF Header EI_MAG1 incorrect.\n");
		return false;
	}
	if(hdr->e_ident[EI_MAG2] != ELFMAG2)
	{
		printf("ELF Header EI_MAG2 incorrect.\n");
		return false;
	}
	if(hdr->e_ident[EI_MAG3] != ELFMAG3)
	{
		printf("ELF Header EI_MAG3 incorrect.\n");
		return false;
	}
	return true;
}
bool ElfCheckSupported(Elf32_Ehdr *hdr)
{
	if(!elf_check_file(hdr))
	{
		printf("Invalid ELF File.\n");
		return false;
	}
	if(hdr->e_ident[EI_CLASS] != ELFCLASS32)
	{
		printf("Unsupported ELF File Class.\n");
		return false;
	}
	if(hdr->e_ident[EI_DATA] != ELFDATA2LSB)
	{
		printf("Unsupported ELF File byte order.\n");
		return false;
	}
	if(hdr->e_machine != EM_386)
	{
		printf("Unsupported ELF File target.\n");
		return false;
	}
	if(hdr->e_ident[EI_VERSION] != EV_CURRENT)
	{
		printf("Unsupported ELF File version.\n");
		return false;
	}
	if(hdr->e_type != ET_REL && hdr->e_type != ET_EXEC)
	{
		printf("Unsupported ELF File type.\n");
		return false;
	}
	return true;
}
static inline void* elf_load_rel(Elf32_Ehdr* hdr) {
	int result;
	result = elf_load_stage1(hdr);
	if(result == ELF_RELOC_ERR) {
		printf("Unable to load ELF file.\n");
		return nullptr;
	}
	result = elf_load_stage2(hdr);
	if(result == ELF_RELOC_ERR) {
		printf("Unable to load ELF file.\n");
		return nullptr;
	}
	// TODO : Parse the program header (if present)
	return (void *)hdr->e_entry;
}

void* elf_load_file(void* file) {
	Elf32_Ehdr *hdr = (Elf32_Ehdr *)file;
	if(!elf_check_supported(hdr)) {
		printf("ELF File cannot be loaded.\n");
		return;
	}
	switch(hdr->e_type) {
		case ET_EXEC:
			// TODO : Implement
			return NULL;
		case ET_REL:
			return elf_load_rel(hdr);
	}
	return NULL;
}
