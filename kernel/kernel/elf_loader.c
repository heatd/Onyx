/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>

#include <kernel/vfs.h>
#include <kernel/elf.h>
#include <kernel/vmm.h>
#include <kernel/modules.h>
static Elf64_Shdr *strtab = NULL;
static Elf64_Shdr *symtab = NULL;
static Elf64_Shdr *shstrtab = NULL;
static inline char *elf_get_string(Elf64_Ehdr *hdr, Elf64_Word off)
{
	return (char*)hdr + strtab->sh_offset + off;
}
static inline char *elf_get_shstring(Elf64_Ehdr *hdr, Elf64_Word off)
{
	return (char*)hdr + shstrtab->sh_offset + off;
}
static inline Elf64_Sym *elf_get_sym(Elf64_Ehdr *hdr, char *symbolname)
{
	Elf64_Sym *syms = (Elf64_Sym*) ((char*) hdr + symtab->sh_offset);
	
	for(unsigned int i = 1; i < symtab->sh_size / symtab->sh_entsize; i++)
	{
		if(!strcmp(elf_get_string(hdr, syms[i].st_name), symbolname))
		{
			return &syms[i];
		}
	}
	return NULL;
}
static inline char *elf_get_reloc_str(Elf64_Ehdr *hdr, Elf64_Shdr *strsec, Elf64_Off off)
{
	return (char*)hdr + strsec->sh_offset + off;
}
uintptr_t get_kernel_sym_by_name(const char* name);
uintptr_t elf_resolve_symbol(Elf64_Ehdr *hdr, Elf64_Shdr *sections, Elf64_Shdr *target, size_t sym_idx)
{
	Elf64_Sym *symbol = (Elf64_Sym*)((char*)hdr + symtab->sh_offset);
	symbol = &symbol[sym_idx];
	Elf64_Shdr *stringtab = &sections[symtab->sh_link];
	uintptr_t sym = symbol->st_value;
	if (symbol->st_shndx == SHN_UNDEF)
	{
		const char *name = elf_get_reloc_str(hdr, stringtab, symbol->st_name);
		uintptr_t val = get_kernel_sym_by_name(name);
		if(val)
			return val;
		else
		{
			if(ELF64_ST_BIND(symbol->st_info) & STB_WEAK)
				return 0;
			else
			{
				return 1;
			}
		}
	}
	else if(symbol->st_shndx == SHN_ABS)
		return symbol->st_value;
	else
	{
		Elf64_Shdr *tar = &sections[symbol->st_shndx];
		return (uintptr_t)hdr + symbol->st_value + tar->sh_offset;
	}
	return 1;
}
int elf_relocate_addend(Elf64_Ehdr *hdr, Elf64_Rela *rela, Elf64_Shdr *section)
{
	Elf64_Shdr *sections = (Elf64_Shdr*)((char*)hdr + hdr->e_shoff); 
	Elf64_Shdr *target_section = &sections[section->sh_info];
	uintptr_t addr = (uintptr_t)hdr + target_section->sh_offset;
	uintptr_t *p = (uintptr_t*)(addr + rela->r_offset);
	size_t sym_idx = ELF64_R_SYM(rela->r_info);
	if(sym_idx != SHN_UNDEF)
	{
		uintptr_t sym = elf_resolve_symbol(hdr, sections, target_section, sym_idx);
		switch (ELF64_R_TYPE(rela->r_info))
		{
			case R_X86_64_NONE: break;
			case R_X86_64_64:
				*p = RELOCATE_R_X86_64_64(sym, rela->r_addend);
				break;
			case R_X86_64_32S:
				*p = RELOCATE_R_X86_64_32S(sym, rela->r_addend);
				break;
			case R_X86_64_32:
				*p = RELOCATE_R_X86_64_32(sym, rela->r_addend);
				break;
			case R_X86_64_PC32:
				*p = RELOCATE_R_X86_64_PC32(sym, rela->r_addend, (uintptr_t) p);
				break;
			default:
				printf("Unsuported relocation!\n");
				return 1;
		}
	}
	return 0;
}
static Elf64_Rela * rela_table = NULL;
static size_t rela_ent_size = 0;
static size_t rela_size = 0;
/* Shared version of elf_parse_program_headers*/
_Bool elf_parse_program_headers_s(void *file)
{
	Elf64_Ehdr *hdr = (Elf64_Ehdr *) file;
	Elf64_Phdr *phdrs = (Elf64_Phdr *) ((char *) file + hdr->e_phoff);
	for(Elf64_Half i = 0; i < hdr->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_LOAD)
		{
			size_t pages = phdrs[i].p_memsz / 4096;
			if (!pages || pages % 4096)
				pages++;
			phdrs[i].p_vaddr = (Elf64_Addr) vmm_allocate_virt_address(0, pages, VMM_TYPE_SHARED, VMM_WRITE | VMM_USER);
			vmm_map_range(phdrs[i].p_vaddr, pages, VMM_WRITE | VMM_USER);
			printf("[ELF] virtual addresses %p - %p\n", phdrs[i].p_vaddr, phdrs[i].p_vaddr + PAGE_SIZE * pages);
			memcpy((void*) phdrs[i].p_vaddr, (void *) ((char *) file + phdrs[i].p_offset),  phdrs[i].p_filesz);
		}
		if(phdrs[i].p_type == PT_DYNAMIC)
		{
			/* Found the dynamic section, very important, as it contains vital information for loading */
			Elf64_Dyn *d = (Elf64_Dyn*)((char*) file + phdrs[i].p_offset);
			for(int i = 0; d[i].d_tag != DT_NULL; i++)
			{
				puts("elf: dynamic tag found");
				/* Here we handle the different tag types that might appear on the DYNAMIC array */
				switch(d[i].d_tag)
				{
					/* We ignore the entries that we're not going to use, or that are never going to come up
					 * while we are loading the interpreter(ld-spartix.so by default)
					*/
					case DT_RELASZ:
					{
						rela_size = d[i].d_un.d_val;
						break;
					
					}
					case DT_STRTAB:
					{
						strtab = (Elf64_Shdr *) ((char*) file + d[i].d_un.d_ptr);
						break; 
					}
					case DT_SYMTAB:
					{
						symtab = (Elf64_Shdr *) ((char*) file + d[i].d_un.d_ptr);
						break;
					}
					case DT_RELA:
					{
						rela_table = (Elf64_Rela *) ((char*) file + d[i].d_un.d_ptr);
						break;
					}
					case DT_RELAENT:
					{
						rela_ent_size = d[i].d_un.d_val;
						break;
					}

				}
			}
						/* 
			 * Start to do relocations
			 * Ok, right here we need to start processing the Rela table,
			 * and getting the section associated with it. After we get the section header,
			 * we need to compare it against the program headers looking for the program header that
			 * contains the .rela.xxxxx section we're processing
			*/
			size_t num_rela_ent = rela_size / rela_ent_size;
			printf("eu\n");
			for(unsigned int j = 0; j < num_rela_ent; j++)
			{
				uint32_t sidx = ELF64_R_INFO(rela_table[j].r_info, ELF64_R_TYPE(rela_table[j].r_info));
				printf("Section index (%u)\n", sidx);
				Elf64_Shdr *sections = (Elf64_Shdr *)((char*) file + hdr->e_shoff);
				Elf64_Shdr *rela_sec = &sections[sidx];
				for(Elf64_Half k = 0; k < hdr->e_phnum; k++)
				{
					if(phdrs[k].p_type == PT_NULL)
						continue;
					if(rela_sec->sh_offset == phdrs[k].p_offset || 
						rela_sec->sh_offset <= phdrs[k].p_offset + phdrs[k].p_filesz && rela_sec->sh_offset > phdrs[k].p_offset)
					{
						puts("Found the closest section!\n");
						printf("Rela offset: %x\n", rela_table[j].r_offset);
						break;
					}
				}
			}
		}
	}
	return 0;
}
int elf_load_pie(char *path)
{
	printf("elf: loading interp %s\n", path);
	if(!path)
		return errno = EINVAL, 1;
	if(*path == '\0')
		return errno = EINVAL, 1;
	vfsnode_t *f = open_vfs(fs_root, path);
	if(!f)
	{
		perror("open_vfs: ");
		return -1;
	}
	char *file = malloc(f->size);
	if(!file)
	{
		perror("malloc: ");
		return -1;
	}
	size_t read = read_vfs(0, f->size, file, f);
	if(read != f->size)
	{
		perror("read_vfs: ");
		free(file);
		close_vfs(file);
		free(f);
		return -1;
	}
	Elf64_Ehdr *header = (Elf64_Ehdr*) file;
	if(elf_is_valid(header) == false)
	{
		printf("elf: invalid interpreter!\n");
		free(file);
		close_vfs(f);
		free(f);
		return errno = EINVAL, -1;
	}
	int ret = elf_parse_program_headers_s(file);
	printf("elf_parse_program_headers_s returned %u\n", ret);
	while(1);
	return 0;
}
_Bool elf_parse_program_headers(void *file)
{
	Elf64_Ehdr *hdr = (Elf64_Ehdr *) file;
	Elf64_Phdr *phdrs = (Elf64_Phdr *) ((char *) file + hdr->e_phoff);
	for (Elf64_Half i = 0; i < hdr->e_phnum; i++) {
		if (phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_INTERP)
		{
			printf("This program needs an interpreter!\n");
			printf("Interpreter: %s\n", (char*)file + phdrs[i].p_offset);
			elf_load_pie((char*)file + phdrs[i].p_offset);
		}
		if (phdrs[i].p_type == PT_LOAD)
		{
			size_t pages = phdrs[i].p_memsz / 4096;
			if (!pages || pages % 4096)
				pages++;
			vmm_reserve_address((void *) (phdrs[i].p_vaddr & 0xFFFFFFFFFFFFF000), pages, VMM_TYPE_REGULAR, VMM_WRITE | VMM_USER);
			void *mem = vmm_map_range((void *) (phdrs[i].p_vaddr & 0xFFFFFFFFFFFFF000), pages, VMM_WRITE | VMM_USER);
			memcpy((void*) phdrs[i].p_vaddr, (void *) ((char *) file + phdrs[i].p_offset),  phdrs[i].p_filesz);			
		}
	}
	return true;
}

_Bool elf_is_valid(Elf64_Ehdr *header)
{
	if (header->e_ident[EI_MAG0] != 0x7F || header->e_ident[EI_MAG1] != 'E' || header->e_ident[EI_MAG2] != 'L' || header->e_ident[EI_MAG3] != 'F')
		return false;
	if (header->e_ident[EI_CLASS] != ELFCLASS64)
		return false;
	if (header->e_ident[EI_DATA] != ELFDATA2LSB)
		return false;
	if (header->e_ident[EI_VERSION] != EV_CURRENT)
		return false;
	if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV)
		return false;
	if (header->e_ident[EI_ABIVERSION] != 0)	/* SYSV specific */
		return false;
	return true;
}

void *elf_load(void *file)
{
	if (!file)
		return errno = EINVAL, NULL;
	/* Check if its elf64 file is invalid */
	if (!elf_is_valid((Elf64_Ehdr *) file))
		return errno = EINVAL, NULL;
	elf_parse_program_headers(file);
	return (void *) ((Elf64_Ehdr *) file)->e_entry;
}
void *elf_load_kernel_module(void *file, void **fini_func)
{
	printf("Loading module %p\n", file);
	if (!file)
		return errno = EINVAL, NULL;
	/* Check if its elf64 file is invalid */
	Elf64_Ehdr *header = (Elf64_Ehdr*) file;
	if (!elf_is_valid(header))
		return errno = EINVAL, NULL;
	Elf64_Shdr *sections = (Elf64_Shdr*)((char*)file + header->e_shoff);
	shstrtab = &sections[header->e_shstrndx];
	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(!strcmp(elf_get_shstring(header, sections[i].sh_name), ".symtab"))
			symtab = &sections[i];
		if(!strcmp(elf_get_shstring(header, sections[i].sh_name), ".strtab"))
			strtab = &sections[i];
	}
	uintptr_t first_address = 0;
	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(sections[i].sh_flags & SHF_ALLOC) 
		{
			void *mem = allocate_module_memory(sections[i].sh_size);
			if(i == 1) first_address = (uintptr_t) mem;
			if(sections[i].sh_type == SHT_NOBITS)
				memset(mem, 0, sections[i].sh_size);
			else
				memcpy(mem, (char*) file + sections[i].sh_offset, sections[i].sh_size);
			sections[i].sh_offset = (Elf64_Off) mem - (Elf64_Off) header;
		}
	}
	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(sections[i].sh_type == SHT_RELA)
		{
			Elf64_Rela *r = (Elf64_Rela*)((char*)file + sections[i].sh_offset);
			for(size_t j = 0; j < sections[i].sh_size / sections[i].sh_entsize; j++)
			{
				Elf64_Rela *rela = &r[j];
				if(elf_relocate_addend(header, rela, &sections[i]) == 1)
				{
					printf("Could relocate the kernel module!\n");
					return errno = EINVAL, NULL;
				}
			}
		}
	}
	Elf64_Sym *init_sym = (Elf64_Sym*)((uintptr_t) elf_get_sym(header, "module_init"));
	void *sym = (void*)(init_sym->st_value + first_address);
	init_sym = (Elf64_Sym*)((uintptr_t) elf_get_sym(header, "module_fini"));
	void *fini = (void*)(init_sym->st_value + first_address);
	*fini_func = fini;
	return sym;
}
