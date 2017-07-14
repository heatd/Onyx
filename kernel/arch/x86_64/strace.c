/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <multiboot2.h>
#include <math.h>

#include <kernel/task_switching.h>
#include <kernel/elf.h>
#include <kernel/panic.h>
#define DEFAULT_UNWIND_NUMBER 6
void itoa(uint64_t i, unsigned int base, char *buf, _Bool is_upper);
static inline void get_frame_pointer(uint64_t **ptr)
{
	/* This piece of code uses something important in the SYSV AMD64 calling convention.
	 * The frame address of a function is stored in the RBP register,
	 * which allows us to skip the variables used by the stack_trace function,
	 * which by turn makes the code slightly faster and less confusing
	 */
	__asm__ __volatile__("mov %%rbp, %0":"=m"(*ptr)::"memory");
}
char *resolve_sym(void *address);
__attribute__((no_sanitize_undefined))
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
		if(thread)
		{
			if((uint64_t*)*rbp >= thread->kernel_stack_top)
				break;
		}
		if(!(void*)*(rbp+1))
			break;
		char *s = resolve_sym((void*)*(rbp+1));
		if(!s)
			break;
		printk("Stack trace #%d: %s\n", i, s);
		rbp = (uint64_t*)*rbp;
		if(!rbp)
			break;
		return_addresses++;
	}
	uint64_t *retaddrbuf = malloc(sizeof(uint64_t) * return_addresses);
	if(!retaddrbuf)
	{
		panic("stack trace: oom\n");
	}
	memset(retaddrbuf, 0, sizeof(uint64_t) * return_addresses);

	return retaddrbuf;
}
/* Maybe it's better to put this section in another file */
Elf64_Shdr *strtabs = NULL;
Elf64_Shdr *symtab = NULL;
char *strtab = NULL;
uintptr_t min(uintptr_t x, uintptr_t y);
__attribute__((no_sanitize_undefined))
char *elf_get_string(Elf64_Word off)
{
	return strtab + off;
}
__attribute__((no_sanitize_undefined))
uintptr_t get_kernel_sym_by_name(const char *name)
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
	return 0;

}
__attribute__((no_sanitize_undefined))
char *resolve_sym(void *address)
{
	size_t num = symtab->sh_size / symtab->sh_entsize;
	Elf64_Sym *syms = (Elf64_Sym*)(symtab->sh_addr + 0xFFFFFFFF80000000);
	for(size_t i = 1; i < num; i++)
	{
		if(syms[i].st_value == (Elf64_Addr)address){
			size_t len = strlen(elf_get_string(syms[i].st_name)) + 4;
			char *buf = malloc(len);
			if(!buf)
				return NULL;
			memset(buf, 0, len);
			sprintf(buf, "<%s>", elf_get_string(syms[i].st_name));
			return buf;
		}
	}
	Elf64_Sym *closest_sym = NULL;
	long diff = INT64_MAX;
	Elf64_Addr addr = (Elf64_Addr) address;
	for(size_t i = 1; i < num; i++)
	{
		if(ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC)
			continue;
		long __diff = addr - syms[i].st_value;
		if(__diff < 0)
			continue;
		diff = min(diff, __diff);
		if(diff != __diff)
			continue;
		closest_sym = &syms[i];
	}
	if(!closest_sym)
		return NULL;
	/* Allocate a buffer big enough to hold <STRING_NAME> + <0xDEADDEADDEADDEAD> */
	size_t buf_size = strlen(elf_get_string(closest_sym->st_name)) + 22;
	char *buf = malloc(buf_size);
	if(!buf)
		return NULL;
	memset(buf, 0, buf_size);
	sprintf(buf, "<%s+0x%x>", elf_get_string(closest_sym->st_name), diff);
	return buf;
}
__attribute__((no_sanitize_undefined))
void init_elf_symbols(struct multiboot_tag_elf_sections *restrict secs)
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
}
