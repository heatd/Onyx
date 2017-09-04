/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <onyx/panic.h>

#include <onyx/vfs.h>
#include <onyx/elf.h>
#include <onyx/kernelinfo.h>
#include <onyx/vmm.h>
#include <onyx/modules.h>
#include <onyx/process.h>
#include <onyx/cpu.h>
#include <onyx/random.h>
#include <onyx/log.h>
#include <onyx/envp.h>
#include <onyx/binfmt.h>
#include <onyx/compiler.h>
#include <onyx/binfmt/elf64.h>

#include <pthread_kernel.h>

void *elf_load(struct binfmt_args *args);
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
		return (uintptr_t) hdr + symbol->st_value + tar->sh_offset;
	}
	return 1;
}

__attribute__((no_sanitize_undefined))
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
				printk("Unsuported relocation!\n");
				return 1;
		}
	}
	return 0;
}

bool elf_is_valid(Elf64_Ehdr *header)
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

void* elf_load(struct binfmt_args *args)
{
	Elf64_Ehdr *header = malloc(sizeof(Elf64_Ehdr));
	if(!header)
		return errno = EINVAL, NULL;
	read_vfs(0, 0, sizeof(Elf64_Ehdr), header, args->file);

	void *entry = NULL;
	switch(header->e_ident[EI_CLASS])
	{
		case ELFCLASS32:
			free(header);
			/* TODO: Add an elf32 loader */
			return errno = EINVAL, NULL;
		case ELFCLASS64:
			entry = elf64_load(args, header);
			break;
	}
	
	free(header);
	
	if(args->needs_interp)
		entry = bin_do_interp(args);
	return entry;
}

void *elf_load_kernel_module(void *file, void **fini_func)
{
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
	_Bool modinfo_found = 0;
	for(size_t i = 0; i < header->e_shnum; i++)
	{
			if(!strcmp(elf_get_shstring(header, sections[i].sh_name), ".modinfo"))
			{
				modinfo_found = 1;

				char *parse = (char*) file + sections[i].sh_offset;
				char *kver = NULL;
				for(size_t j = 0; j < sections[i].sh_size; j++)
				{
					if(*parse != 'k' && *(parse+1) != 'e' && *(parse+2) != 'r' && *(parse+3) != 'n' && *(parse+4) != 'e' && *(parse+5) != 'l' && *(parse+6) != '=')
					{
						kver = parse + strlen("kernel=") - 1;
						break;
					}
					parse++;
				}
				if(!kver)
					return NULL;
				/* Check if the kernel version matches up */
				if(strcmp(OS_RELEASE, kver))
				{
					FATAL("module", "Kernel version does not match with the module!\n");
					return NULL;
				}
			}
	}
	if(!modinfo_found)
		return NULL;	
	uintptr_t first_address = 0;
	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(sections[i].sh_flags & SHF_ALLOC) 
		{
			void *mem = allocate_module_memory(sections[i].sh_size);
			if(first_address == 0) first_address = (uintptr_t) mem;
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
					printk("Couldn't relocate the kernel module!\n");
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

bool elf_is_valid_exec(uint8_t *file)
{
	return elf_is_valid((Elf64_Ehdr*) file);
}

struct binfmt elf_binfmt = {
	.signature = (unsigned char *)"\x7f""ELF",
	.size_signature = 4,
	.callback = elf_load,
	.is_valid_exec = elf_is_valid_exec,
	.next = NULL
};

__init void __elf_init()
{
	install_binfmt(&elf_binfmt);
}
