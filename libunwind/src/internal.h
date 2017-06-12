/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _UNW_INTERNAL
#define _UNW_INTERNAL
#include <elf.h>
#include <unwind.h>
Unwind_info *Unwind_stack(size_t *);

typedef struct
{
	void *file;
	Elf64_Ehdr *header;
	Elf64_Sym *symtab;
	size_t nr_symtab;
	char *strtab;
	char *shstrtab;
} elf_object_t;

elf_object_t *elf_parse(void *file);
char *resolve_sym(uintptr_t address, elf_object_t *object);
#endif
