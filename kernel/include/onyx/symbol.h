/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_SYMBOL_H
#define _ONYX_SYMBOL_H

#include <stdint.h>
#include <stdbool.h>

#include <onyx/elf.h>
#include <onyx/fnv.h>
#include <onyx/module.h>

#define SYMBOL_VIS_LOCAL		0
#define SYMBOL_VIS_GLOBAL		1
#define SYMBOL_VIS_WEAK			(1 << 1)
#define SYMBOL_FUNCTION			(1 << 2)
#define SYMBOL_OBJECT			(1 << 3)

struct symbol
{
	char *name;
	fnv_hash_t name_hash;
	unsigned long value;
	uint8_t visibility;
};

static inline bool is_useful_symbol(Elf64_Sym *sym)
{
	if(sym->st_shndx == SHN_UNDEF)
		return false;
	
	if(ELF64_ST_TYPE(sym->st_info) == STT_FILE ||
	   ELF64_ST_TYPE(sym->st_info) == STT_SECTION ||
	   ELF64_ST_TYPE(sym->st_info) == STT_NOTYPE)
	   return false;

	/* NOTE: We keep LOCAL symbols for debugging (i.e panic stack traces) */
	return true;
}

void setup_kernel_symbols(struct module *m);
int setup_symbol(struct symbol *s, Elf64_Sym *sym, const char *name);

#endif