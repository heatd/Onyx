/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _DYNLINK_H
#define _DYNLINK_H

#include <utils.h>
#include <elf.h>
struct dso
{
	char *name;
	void *file;
	uintptr_t base;
	char *strtab;
	char *shstrtab;
	Elf64_Sym *symtab;
	Elf64_Half nr_symtab;
	Elf64_Sym *dyntab;
	Elf64_Half nr_dyntab;
	char *dynstr;
	void (*init)();
	void (*fini)();
	void *initarray;
	void *finiarray;
	size_t initarraysz;
	size_t finiarraysz;
	int refcount;
	linked_list_t *dependencies;
	struct dso *next;
};

#define fpaddr(function_ptr, dso) ((void (*)())((uintptr_t) function_ptr + dso->base))
typedef int (*prog_entry_t)(int argc, char **argv, char **envp, void *auxv);
#define RELOCATE_R_X86_64_64(S, A) (S + A)
#define RELOCATE_R_X86_64_32(S, A) (S + A)
#define RELOCATE_R_X86_64_16(S, A) (S + A)
#define RELOCATE_R_X86_64_8(S, A) (S + A)
#define RELOCATE_R_X86_64_32S(S, A) (S + A)
#define RELOCATE_R_X86_64_PC32(S, A, P) (S + A - P)
#define RELOCATE_R_X86_64_RELATIVE(B, A) (B + A)
#define RELOCATE_R_X86_64_JUMP_SLOT(S) (S)
#define RELOCATE_R_X86_64_GLOB_DAT(S) (S)
#endif