/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include "internal.h"
static inline uintptr_t min(uintptr_t x, uintptr_t y)
{
	return x < y ? x : y;
}
static inline char *elf_get_string(Elf64_Word off, elf_object_t* obj)
{
	return obj->strtab + off;
}
static inline char *elf_get_shstring(Elf64_Word off, elf_object_t* obj)
{
	return obj->shstrtab + off;
}
static inline void *elf_get_pointer(void *file, Elf64_Off offset)
{
	return (void*)(char*)file + offset;
}
static inline Elf64_Sym *elf_get_sym(size_t idx, elf_object_t *obj)
{
	return &obj->symtab[idx];
}
int verify_elf(void *file)
{
	Elf64_Ehdr *header = (Elf64_Ehdr *) file;
	if (header->e_ident[EI_MAG0] != ELFMAG0 || header->e_ident[EI_MAG1] != ELFMAG1 
		|| header->e_ident[EI_MAG2] != ELFMAG2 || header->e_ident[EI_MAG3] != ELFMAG3)
		return -1;
	if (header->e_ident[EI_CLASS] != ELFCLASS64)
		return -1;
	if (header->e_ident[EI_DATA] != ELFDATA2LSB)
		return -1;
	if (header->e_ident[EI_VERSION] != EV_CURRENT)
		return -1;
	if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV)
		return -1;
	if (header->e_ident[EI_ABIVERSION] != 0)	/* SYSV specific */
		return -1;
	return 0;
}
elf_object_t *elf_parse(void *file)
{
	if(verify_elf(file) < 0)
	{
		fprintf(stderr, "libunwind: Invalid ELF file\n");
		return NULL;
	}
	elf_object_t *object = malloc(sizeof(elf_object_t));
	if(!object)
		return NULL;
	memset(object, 0, sizeof(elf_object_t));
	object->file = file;
	Elf64_Ehdr *header = (Elf64_Ehdr *) file;

	object->header = header;
	Elf64_Shdr *sections = elf_get_pointer(object->file, header->e_shoff);
	size_t n_sections = header->e_shnum;
	object->shstrtab = elf_get_pointer(object->file, sections[header->e_shstrndx].sh_offset);
	for(Elf64_Half i = 0; i < n_sections; i++)
	{
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".strtab") == 0)
			object->strtab = elf_get_pointer(object->file, sections[i].sh_offset);
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".symtab") == 0)
		{
			object->symtab = elf_get_pointer(object->file, sections[i].sh_offset);
			object->nr_symtab = sections[i].sh_size / sections[i].sh_entsize;
		}
	}
	return object;
}
char *resolve_sym(uintptr_t address, elf_object_t *object)
{
	Elf64_Sym *syms = object->symtab;
	for(size_t i = 1; i < object->nr_symtab; i++)
	{
		if(syms[i].st_value == address)
		{
			char *elf_name = elf_get_string(syms[i].st_name, object);
			char *buf = malloc(strlen(elf_name) + 3);
			if(!buf)
				return NULL;
			memset(buf, 0, strlen(elf_name) + 3);
			snprintf(buf, strlen(elf_name) + 3, "<%s>", elf_name);
			return buf;
		}
	}
	Elf64_Sym *closest_sym = NULL;
	long diff = INT64_MAX;
	Elf64_Addr addr = (Elf64_Addr) address;
	for(size_t i = 1; i < object->nr_symtab; i++)
	{
		if(ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC)
			continue;
		long __diff = addr - syms[i].st_value;
		if(__diff < 0)
			continue;
		if((unsigned long) __diff > syms[i].st_size)
			continue;
		diff = min(diff, __diff);
		if(diff != __diff)
			continue;
		closest_sym = &syms[i];
	}
	if(!closest_sym)
		return NULL;
	size_t buf_size = strlen(elf_get_string(closest_sym->st_name, object)) + 22;
	char *buf = malloc(buf_size);
	if(!buf)
		return NULL;
	memset(buf, 0, buf_size);
	snprintf(buf, buf_size, "<%s+0x%"PRIx64">", elf_get_string(closest_sym->st_name, object), diff);
	return buf;
}
