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
#include <kernel/fs.h>
#include <stdbool.h>
#include <errno.h>
#include <multiboot.h>
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
				      MAP_WRITE|MAP_USER);
				memset((void *) prog_hdr[i].p_vaddr, 0,
				       prog_hdr[i].p_memsz);
			}
			kmmap(prog_hdr[i].p_vaddr,
			      prog_hdr[i].p_memsz / 1024 + 1024,
			      MAP_WRITE|MAP_USER);
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
extern multiboot_info_t *mbt;
static Elf32_Sym *ksymtab = NULL;
static Elf32_Shdr *kstrtab;
Elf32_Sym *get_ksymtab()
{
	return ksymtab;
}
char *kstrtable;
static int num_entries;
void *elf_lookup_symbol(const char *name)
{
	/* If we havent initialized the ksymtab yet, do it now*/
	if( ksymtab == NULL) {
		multiboot_elf_section_header_table_t *elf = &mbt->u.elf_sec;
		Elf32_Shdr *tab = (Elf32_Shdr *)elf->addr;
		kstrtab = &tab[elf->shndx];
		kstrtable = (char *)kstrtab->sh_addr;
		for(unsigned int i = 0; i < elf->num; i++) {
			if(tab[i].sh_type == SHT_SYMTAB) {
				printf("Found ksymtab at %p\n",tab[i].sh_addr);
				ksymtab = (Elf32_Sym *)tab[i].sh_addr;
				num_entries = tab[i].sh_size / sizeof(Elf32_Sym);
			}
			if(tab[i].sh_type == SHT_STRTAB) {
				if(&tab[i] != kstrtab) {
					kstrtab = &tab[i];
					kstrtable = (char *)kstrtab->sh_addr;
				}
			}
		}
	}
	for(int i = 0; i < num_entries; i++) {
		Elf32_Sym *sym = &ksymtab[i];
		if(!strcmp((char *)kstrtable + sym->st_name,(char *)name))
			return (void *)sym->st_value;
	}
	return NULL;
}
static Elf32_Shdr *strtab;
static int elf_get_symval(Elf32_Ehdr *hdr, int table, unsigned int idx)
{
	if(table == SHN_UNDEF || idx == SHN_UNDEF) return 0;
	Elf32_Shdr *shdr = elf_get_section_table(hdr);
	Elf32_Shdr *symtab = elf_access_section(shdr, table);
	uint32_t symtab_entries = symtab->sh_size / symtab->sh_entsize;
	if(idx >= symtab_entries) {
		printf("Symbol Index out of Range (%d:%u).\n", table, idx);
		return ELF_RELOC_ERR;
	}

	int symaddr = (int)hdr + symtab->sh_offset;
	Elf32_Sym *symbol = &((Elf32_Sym *)symaddr)[idx];
	if(symbol->st_shndx == SHN_UNDEF) {
		// External symbol, lookup value
		Elf32_Shdr *strtab = elf_access_section(shdr, symtab->sh_link);
		const char *name = (const char *)hdr + strtab->sh_offset + symbol->st_name;
		void *target = elf_lookup_symbol(name);

		if(target == NULL) {
			// Extern symbol not found
			if(ELF32_ST_BIND(symbol->st_info) & STB_WEAK) {
				// Weak symbol initialized as 0
				return 0;
			} else {
				printf("Undefined External Symbol : %s.\n", name);
				return ELF_RELOC_ERR;
			}
		} else {
			return (int)target;
		}
	} else if(symbol->st_shndx == SHN_ABS) {
	// Absolute symbol
	return symbol->st_value;
} else {
	// Internally defined symbol
	Elf32_Shdr *target = elf_access_section(shdr, symbol->st_shndx);
	return (int)hdr + symbol->st_value + target->sh_offset;
}
}
static Elf32_Shdr *symtab = NULL;
size_t elf_parse_sections(Elf32_Ehdr *hdr)
{
	Elf32_Shdr *shdr = elf_get_section_table(hdr);
	size_t size = 0;
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
		if( section->sh_flags & SHF_ALLOC ) {
			size += section->sh_size;
		}
	}
	return size;
}
# define DO_386_32(S, A)	((S) + (A))
# define DO_386_PC32(S, A, P)	((S) + (A) - (P))

static int elf_do_reloc(Elf32_Ehdr *hdr, Elf32_Rel *rel, Elf32_Shdr *reltab) {
	Elf32_Shdr *shdr = elf_get_section_table(hdr);
	Elf32_Shdr *target = elf_access_section(shdr, reltab->sh_info);

	int addr = (int)hdr + target->sh_offset;
	int *ref = (int *)(addr + rel->r_offset);
	// Symbol value
	int symval = 0;
	if(ELF32_R_SYM(rel->r_info) != SHN_UNDEF) {
		symval = elf_get_symval(hdr, reltab->sh_link, ELF32_R_SYM(rel->r_info));
		if(symval == ELF_RELOC_ERR) return ELF_RELOC_ERR;
	}
	// Relocate based on type
	switch(ELF32_R_TYPE(rel->r_info)) {
		case R_386_NONE:
			// No relocation
			break;
		case R_386_32:
			// Symbol + Offset
			*ref = DO_386_32(symval, *ref);
			break;
		case R_386_PC32:
			// Symbol + Offset - Section Offset
			*ref = DO_386_PC32(symval, *ref, (int)ref);
			break;
		default:
			// Relocation type not supported, display error and return
			printf("Unsupported Relocation Type (%d).\n", ELF32_R_TYPE(rel->r_info));
			return ELF_RELOC_ERR;
	}
	return symval;
}

int elf_reloc(Elf32_Ehdr *hdr)
{
	Elf32_Shdr *sections = elf_get_section_table(hdr);
	unsigned int i, idx;
	/* Iterate over section headers */
	for(i = 0; i < hdr->e_shnum; i++) {
		Elf32_Shdr *section = &sections[i];

		/* If this is a relocation section */
		if(section->sh_type == SHT_REL) {
			// Process each entry in the table
			for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) {
				Elf32_Rel *reltab = &((Elf32_Rel *)((int)hdr + section->sh_offset))[idx];
				int result = elf_do_reloc(hdr, reltab, section);
				// On error, display a message and return
				if(result == ELF_RELOC_ERR) {
					throw_error(0xFF,"Failed to relocate symbol.");
					return ELF_RELOC_ERR;
				}
			}
		}
	}
	return 0;
}
uintptr_t elf_load_sections(Elf32_Ehdr *hdr, size_t size)
{
	Elf32_Shdr *shdr = elf_get_section_table(hdr);

	char *file = (char *)hdr;

	size_t pages = size / 4096;
	if(size % 4096)
		pages++;
	uintptr_t base = (uintptr_t) vmm_alloc_addr(pages,true);
	kmmap(base ,pages,MAP_KERNEL | MAP_WRITE);
	for(int i = 0; i < hdr->e_shnum; i++) {

		Elf32_Shdr *section = elf_access_section(shdr,i);

		if(section->sh_flags & SHF_ALLOC) {

			uintptr_t addr = (uintptr_t) section->sh_offset + base;
			memcpy((void *)addr,file + section->sh_offset,section->sh_size);
		}
	}
	return base;
}
kthread_t *elf_load_file(char *file)
{
	Elf32_Ehdr *header = (Elf32_Ehdr *) file;

	if (!elf_check_supported(header))
		return NULL;

	size_t size = elf_parse_sections(header);

	elf_reloc(header);

	uintptr_t base_addr = 0;

	if(header->e_type == ET_REL) {
		base_addr = elf_load_sections(header,size);

		Elf32_Sym *sym = (Elf32_Sym *)(file + symtab->sh_offset);
		int no_entries = symtab->sh_size / sizeof(Elf32_Sym);
		for( int i = 0; i < no_entries; i++) {
			char *name = (char *)header + strtab->sh_offset + sym[i].st_name;
			if (!strcmp(name, (char *)"module_init")) {
				Elf32_Shdr *shdr = elf_get_section_table(header);
				shdr = elf_access_section(shdr,sym[i].st_shndx);
				header->e_entry = base_addr + sym[i].st_value + shdr->sh_offset;
			}
		}
	}else {

	Elf32_Phdr *prog_hdr = (Elf32_Phdr *) (file + header->e_phoff);

	if (elf_parse_program_header(prog_hdr, header->e_phnum, file) == 1) {

		throw_error(0x4, "Invalid Load address");
		return NULL;
	}
	}
	kthread_t *kt = kthread_create((kthread_entry_point_t) (header->e_entry), true, 0,0);

	return kt;
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
