/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <kernel/task_switching.h>
#include <kernel/elf.h>
#include <multiboot2.h>
#define DEFAULT_UNWIND_NUMBER 6
inline void get_frame_pointer(uint64_t **ptr)
{
	/* This piece of code uses something important in the SYSV AMD64 calling convention.
	 * The frame address of a function is store in the RBP register,
	 * which allows us to skip the variables used by the stack_trace function,
	 * which by turn makes the code slightly faster and less confusing
	 */
	asm volatile("mov %%rbp, %0":"=m"(*ptr)::"memory");
}
extern uintptr_t __stack_chk_guard;
char *resolve_sym(void *address);
void *stack_trace()
{
	uint64_t *stack = NULL;
	get_frame_pointer(&stack);
	size_t return_addresses = 0;
	// Get all the unwinds possible using threading structures
	thread_t *thread = get_current_thread();
	size_t unwinds_possible = 0;
	if(!thread) // We're still in single tasking mode, just use a safe default
		unwinds_possible = DEFAULT_UNWIND_NUMBER; // Early kernel functions don't nest a lot
	else
		unwinds_possible = 1024; /* It's safe to say the stack won't grow larger than this,
		 but I might implement something better after this */
	uint64_t *rbp = stack;
	for(size_t i = 0; i < unwinds_possible; i++)
	{
		if((uint64_t*)*rbp >= thread->kernel_stack_top)
			break;
		printf("Stack trace #%d: %s\n", i, resolve_sym((void*)*(rbp+1)));
		rbp = (uint64_t*)*rbp;
		return_addresses++;
	}
	uint64_t *retaddrbuf = malloc(sizeof(uint64_t) * return_addresses);
	memset(retaddrbuf, 0, sizeof(uint64_t) * return_addresses);
	get_frame_pointer(&rbp);
	for(size_t i = 0; i < return_addresses; i++)
	{
		if((uint64_t*)*rbp >= thread->kernel_stack_top)
			break;
		retaddrbuf[i] = *(rbp+1);
		rbp = (uint64_t*)*rbp;
		return_addresses++;
	}
	return retaddrbuf;
}
/* Maybe it's better to put this section in another file */
Elf64_Shdr *strtabs = NULL;
Elf64_Shdr *symtab = NULL;
char *strtab = NULL;
char *elf_get_string(Elf64_Word off)
{
	return strtab + off;
}
uintptr_t get_kernel_sym_by_name(char *name)
{
	size_t num = symtab->sh_size / symtab->sh_entsize;
	Elf64_Sym *syms = (Elf64_Sym*)(symtab->sh_addr + 0xFFFFFFFF80000000);
	for(size_t i = 1; i < num; i++)
	{
		if(!strcmp(elf_get_string(syms[i].st_name), name))
		{
			return syms[i].st_value;
		}
	}
}
char *resolve_sym(void *address)
{
	size_t num = symtab->sh_size / symtab->sh_entsize;
	Elf64_Sym *syms = (Elf64_Sym*)(symtab->sh_addr + 0xFFFFFFFF80000000);
	for(size_t i = 1; i < num; i++)
	{
		if(syms[i].st_value == (Elf64_Addr)address){
			size_t len = strlen(elf_get_string(syms[i].st_name)) + 3;
			char *buf = malloc(len);
			*buf = '<';
			strcpy(buf+1, elf_get_string(syms[i].st_name));
			char *endofstr = buf + strlen(elf_get_string(syms[i].st_name));
			*++endofstr = '>';
			return buf;
		}
	}
	Elf64_Sym *closest_sym = NULL;
	for(size_t i = 1; i < num; i++)
	{
		if(syms[i].st_value < (Elf64_Addr)address && syms[i].st_value + syms[i].st_size >= (Elf64_Addr)address)
		{
			closest_sym = &syms[i];
			break;
		}
	}
	char buff[120] = {0};
	memcpy(buff, "0x", 2);
	itoa((uint64_t)address - closest_sym->st_value, 16, buff+2, 1);
	size_t lenof = strlen(buff);
	char *ret = malloc(strlen(elf_get_string(closest_sym->st_name) + lenof + 7));
	*ret = '<';
	strcpy(ret+1, elf_get_string(closest_sym->st_name));
	char *endof = ret+1 + strlen(elf_get_string(closest_sym->st_name));
	*endof++ = ' ';
	*endof++ = '+';
	*endof++ = ' ';
	strcpy(endof, buff);
	endof +=strlen(buff);
	*endof = '>';
	return ret;
}
void init_elf_symbols(struct multiboot_tag_elf_sections *secs)
{
	Elf64_Shdr *sections = (Elf64_Shdr*)(secs->sections);
	strtabs = &sections[secs->shndx];
	strtab = (char*)(strtabs->sh_addr + 0xFFFFFFFF80000000);
	for(unsigned int i = 0; i < secs->num; i++)
	{
		if(!strcmp(".symtab",elf_get_string(sections[i].sh_name)))
		{
			symtab = &sections[i];
		}
		if(!strcmp(".strtab",elf_get_string(sections[i].sh_name)))
		{
			strtab = (char*)(sections[i].sh_addr + 0xFFFFFFFF80000000);
		}
	}
	resolve_sym(&init_elf_symbols);
}
