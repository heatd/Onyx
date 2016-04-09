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
 * File: elf_loader.c
 *
 * Description: Elf Loader
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <kernel/elf_loader.h>
#include <kernel/tty.h>
#include <kernel/mm.h>
#include <kernel/kthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
int elf_parse_program_header(Elf32_Phdr *prog_hdr, Elf32_Half entries,
			     char *file)
{
	for (int i = 0; i <= entries; i++) {
		if (prog_hdr[i].p_type == 1) {
			if (vmm_mark_addr_as_used
			    ((void *) prog_hdr[i].p_vaddr,
			     prog_hdr[i].p_memsz / 1024) == 1) {
				return 1;
			}
			if (prog_hdr[i].p_filesz < prog_hdr[i].p_memsz) {
				/* Its the bss section, zero it out */
				kmmap(prog_hdr[i].p_vaddr,
				      prog_hdr[i].p_memsz / 1024 + 4096,
				      _PDE_WRITABLE);
				memset((void *) prog_hdr[i].p_vaddr, 0,
				       prog_hdr[i].p_memsz);
			}
			kmmap(prog_hdr[i].p_vaddr,
			      prog_hdr[i].p_memsz / 1024 + 1024,
			      _PDE_WRITABLE);
			memcpy((void *) prog_hdr[i].p_vaddr,
			       file + prog_hdr[i].p_offset,
			       prog_hdr[i].p_filesz);
		}
	}
	return 0;
}
inline Elf32_Shdr *elf_get_section_table(Elf32_Ehdr *hdr)
{
	return (Elf32_Shdr *)((char *)hdr + hdr->e_shoff);
}
inline Elf32_Shdr *elf_access_section(Elf32_Shdr *shdr, int idx)
{
	return &shdr[idx];
}
inline char *elf_get_string(Elf32_Ehdr *hdr, Elf32_Shdr *strtab, Elf32_Word off)
{
	char *str = (char *)hdr + strtab->sh_offset;
	if(!str)
		return NULL;
	return str + off;
}
void elf_parse_sections(Elf32_Ehdr *hdr)
{
	Elf32_Shdr *shdr = elf_get_section_table(hdr);
	Elf32_Shdr *strtab = NULL, *symtab = NULL;
	(void) symtab;
	(void) strtab;
	Elf32_Shdr *shstrtab = elf_access_section(shdr,hdr->e_shstrndx);
	for (int i = 0; i < hdr->e_shnum; i++) {
		Elf32_Shdr *section = elf_access_section(shdr,i);
		/* This would be cleaner as a switch statement, but im just
		testing stuff out */
		if ( section->sh_type == SHT_STRTAB ) {
			if ( section == shstrtab )
				continue;
			strtab = section;
		} else if ( section->sh_type == SHT_SYMTAB ) {
			symtab = section;
		}
		if(section->sh_type != SHT_NULL)
			printf("Section Name: %s\n",elf_get_string(hdr,shstrtab,section->sh_name));
	}

	while(1);

}
_Bool elf_load_file(char *file)
{
	Elf32_Ehdr *header = (Elf32_Ehdr *) file;
	if (!elf_check_supported(header))
		return false;
	elf_parse_sections(header);
	Elf32_Phdr *prog_hdr = (Elf32_Phdr *) (file + header->e_phoff);
	if (elf_parse_program_header(prog_hdr, header->e_phnum, file) == 1) {
		throw_error(0x4, "Invalid Load address");
		return false;
	}
	kthread_t *kt =
	    kthread_create((kthread_entry_point_t) header->e_entry);
	kthread_start(kt);
	return true;
}

void throw_error(int errn, const char *err_msg)
{
	errno = errn;
	tty_set_color(0xFF0000);
	printf("[ KERNEL ]( ELF LOADER ) error: %s\n", err_msg);
	tty_set_color(0xC0C0C0);
}

_Bool elf_check_supported(Elf32_Ehdr *header)
{
	if (header->e_ident[EI_MAG0] != ELFMAG0) {
		throw_error(HDR_INV, "Invalid ELF header!");
		return false;
	}
	if (header->e_ident[EI_MAG1] != ELFMAG1) {
		throw_error(HDR_INV, "Invalid ELF header!");
		return false;
	}
	if (header->e_ident[EI_MAG2] != ELFMAG2) {
		throw_error(HDR_INV, "Invalid ELF header!");
		return false;
	}
	if (header->e_ident[EI_MAG3] != ELFMAG3) {
		throw_error(HDR_INV, "Invalid ELF header!");
		return false;
	}
	if (header->e_ident[EI_CLASS] != ELFCLASS32) {
		throw_error(ARCH_INV, "Invalid architecture!");
		return false;
	}
	if (header->e_ident[EI_DATA] != ELFDATA2LSB) {
		throw_error(DATAORDER_INV, "Invalid Byte order!");
		return false;
	}
	if (header->e_type != ET_EXEC) {
		if(header->e_type != ET_REL) {
			throw_error(HDR_INV, "ELF type not loadable by the OS");
			return false;
		}
	}
	return true;
}
