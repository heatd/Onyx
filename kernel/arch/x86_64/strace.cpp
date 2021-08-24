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

#include <onyx/task_switching.h>
#include <onyx/elf.h>
#include <onyx/panic.h>
#include <onyx/vm.h>
#include <onyx/utils.h>
#include <onyx/symbol.h>
#include <onyx/modules.h>

#define DEFAULT_UNWIND_NUMBER 6

static inline void get_frame_pointer(uint64_t **ptr)
{
	/* This piece of code uses something important in the SYSV AMD64 calling convention.
	 * The frame address of a function is stored in the RBP register,
	 * which allows us to skip the variables used by the stack_trace function,
	 * which by turn makes the code slightly faster and less confusing
	 */
	__asm__ __volatile__("mov %%rbp, %0":"=m"(*ptr)::"memory");
}

unsigned long get_ulong_user(void *ptr, bool *error)
{
	unsigned long l = 0;
	if(copy_from_user(&l, ptr, sizeof(unsigned long)) < 0)
	{
		*error = true;
		return 0xffffffffffffffff;
	}

	*error = false;
	return l;
}

void stack_trace_user(uintptr_t *stack)
{
	uint64_t *rbp = stack;
	bool error = false;

	printk("User stack trace:\n");
	int i = 0;
	while(get_ulong_user(rbp, &error) != 0 && error == false)
	{
		uintptr_t rip = get_ulong_user((rbp + 1), &error);

		if(error == true)
			return;
		if(rip == 0)
			return;
		
		printk("<%d> %016lx\n", i++, rip);

		rbp = (uintptr_t *) get_ulong_user(rbp, &error);

		if(error == true)
			return;
	}
	printk("Stack trace ended.\n");
}

char *resolve_sym(void *address);
__attribute__((no_sanitize_undefined))
void stack_trace_ex(uint64_t *stack)
{
	size_t return_addresses = 0;
	// Get all the unwinds possible using threading structures
	thread_t *thread = get_current_thread();
	size_t unwinds_possible = 0;
	if(!thread) // We're still in single tasking mode, just use a safe default
		unwinds_possible = DEFAULT_UNWIND_NUMBER; // Early kernel functions don't nest a lot
	else
		unwinds_possible = 1024; /* It's safe to say the stack won't grow larger than this */

	uint64_t *rbp = stack;
	for(size_t i = 0; i < unwinds_possible; i++)
	{
		/*if(thread)
		{
			if((uint64_t*) *rbp >= thread->kernel_stack_top)
				break;
		}*/

		if(!(void*) *(rbp + 1))
			break;
		
		char *s = resolve_sym((void*) *(rbp + 1));
		if(!s)
			break;
		
		printk("Stack trace #%lu: %s\n", i, s);

		free(s);

		rbp = (uint64_t*)*rbp;
		if(!rbp)
			break;

		return_addresses++;
	}
}

void stack_trace(void)
{
	uint64_t *stack = NULL;
	get_frame_pointer(&stack);
	stack_trace_ex(stack);
}

/* Maybe it's better to put this section in another file */
Elf64_Shdr *strtabs = NULL;
Elf64_Shdr *symtab = NULL;
char *strtab = NULL;

__attribute__((no_sanitize_undefined))
char *elf_get_string(Elf64_Word off)
{
	return strtab + off;
}

struct symbol_walk_context
{
	struct module *module;
	unsigned long addr;
	long diff;
	struct symbol *sym;
	bool free_after;
};

static bool sym_iterate_each_module(struct module *m, void *p)
{
	struct symbol_walk_context *c = (symbol_walk_context *) p;

	const size_t nr_syms = m->nr_symtable_entries;

	for(size_t i = 0; i < nr_syms; i++)
	{
		struct symbol *s = &m->symtable[i];

		/* Skip if it's not a function */
		if(!(s->visibility & SYMBOL_FUNCTION))
			continue;
		
		/* Check if it's inside the bounds of the symbol */

		if(!((unsigned long) c->addr >= s->value && (unsigned long) c->addr < s->value + s->size))
			continue;
	
		long diff = c->addr - s->value;

		/* If addr < symbol value, it can't be it */
		if(diff < 0)
			continue;
		else if(diff == 0)
		{
			/* Found it! This is the one! Return. */
			c->sym = s;
			c->module = m;

			return false;
		}
		else
		{
			if(diff < c->diff)
			{
				c->diff = diff;
				c->sym = s;
				c->module = m;
			}
		}
	}

	return true;
}

static struct symbol *iterate_symbols_struct_syms(struct symbol_walk_context *c)
{
	c->diff = LONG_MAX;

	for_each_module(sym_iterate_each_module, c);

	return c->sym;
}

static struct symbol *iterate_symbols_elf_tables(struct symbol_walk_context *c)
{
	if(!symtab)
		return NULL;
	const size_t num = symtab->sh_size / symtab->sh_entsize;
	Elf64_Sym *syms = (Elf64_Sym*)(symtab->sh_addr + PHYS_BASE);

	Elf64_Sym *closest_sym = NULL;
	long diff = LONG_MAX;
	Elf64_Addr addr = (Elf64_Addr) c->addr;

	for(size_t i = 1; i < num; i++)
	{
		Elf64_Sym *sym = &syms[i];
	
		if(ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;
	
		long __diff = addr - sym->st_value;
		if(__diff < 0)
			continue;
		diff = min(diff, __diff);

		if(diff != __diff)
			continue;
		closest_sym = &syms[i];
	}

	if(!closest_sym)
		return NULL;

	/* I don't feel comfortable allocating memory in stack traces */
	struct symbol *s = (symbol *) zalloc(sizeof(*s));

	if(!s)
		return NULL;
	
	s->name = elf_get_string(closest_sym->st_name);
	s->value = closest_sym->st_value;

	c->diff = diff;
	c->module = &core_kernel;
	c->sym = s;
	c->free_after = true;

	return s;
}

static struct symbol *iterate_symbols(struct symbol_walk_context *c)
{
	bool struct_symbols_setup = core_kernel.symtable != NULL;

	if(struct_symbols_setup)
		return iterate_symbols_struct_syms(c);
	else
		return iterate_symbols_elf_tables(c);
}

char *resolve_sym(void *address)
{
	struct symbol_walk_context c = {};
	c.addr = (unsigned long) address;

	if(!iterate_symbols(&c))
		return NULL;

	const char *symbol_name = c.sym->name;
	char *ret = NULL;
	struct module *m = c.module;
	const char *module_prefix = "";

	if(m != &core_kernel)
		module_prefix = m->name;

	if(c.diff)
	{
		
		size_t buffer_size = strlen(module_prefix) + strlen("::")
				     + strlen(symbol_name) + strlen("<>")
				     + strlen(" + ") + strlen("0xffffffffffffffff") + 1;
		char *buf = (char *) zalloc(buffer_size);
		if(!buf)
			goto out;
		snprintf(buf, buffer_size, "<%s::%s + %lx>", module_prefix, symbol_name, c.diff);

		ret = buf;
	}
	else
	{
		size_t buffer_size = strlen(module_prefix) + strlen("::")
				     + strlen(symbol_name) + strlen("<>") + 1;
		char *buf = (char *) zalloc(buffer_size);
		if(!buf)
			goto out;
		snprintf(buf, buffer_size, "<%s::%s>", module_prefix, symbol_name);

		ret = buf;
	}

out:
	if(c.free_after)
		free(c.sym);

	return ret;
}

__attribute__((no_sanitize_undefined))
void init_elf_symbols(struct multiboot_tag_elf_sections *secs)
{
	secs = (struct multiboot_tag_elf_sections *) ((unsigned long) secs + PHYS_BASE);
	Elf64_Shdr *sections = (Elf64_Shdr*)(secs->sections);
	strtabs = &sections[secs->shndx];
	strtab = (char*)(strtabs->sh_addr + PHYS_BASE);

	for(unsigned int i = 0; i < secs->num; i++)
	{
		if(!strcmp(".symtab", elf_get_string(sections[i].sh_name)))
		{
			symtab = &sections[i];
		}
		if(!strcmp(".strtab", elf_get_string(sections[i].sh_name)))
		{
			strtab = (char*)(sections[i].sh_addr + PHYS_BASE);
		}
	}
}

void reclaim_elf_sections_memory(void);

void setup_kernel_symbols(struct module *m)
{
	const size_t num = symtab->sh_size / symtab->sh_entsize;
	Elf64_Sym *syms = (Elf64_Sym*)(symtab->sh_addr + PHYS_BASE);
	size_t useful_syms = 0;

	for(size_t i = 0; i < num; i++)
	{
		Elf64_Sym *sym = &syms[i];
		if(!is_useful_symbol(sym))
			continue;

		useful_syms++;
	}

	struct symbol *symtab = (symbol *) zalloc(sizeof(struct symbol) * useful_syms);
	
	assert(symtab != NULL);

	for(size_t i = 0, n = 0; i < num; i++)
	{
		Elf64_Sym *sym = &syms[i];
		if(!is_useful_symbol(sym))
			continue;

		/* TODO: Re-use more code between elf.c's module loading and this */
		
		struct symbol *s = &symtab[n];
		assert(setup_symbol(s, sym, elf_get_string(sym->st_name)) == 0);

		n++;
	}

	m->symtable = symtab;
	m->nr_symtable_entries = useful_syms;

	reclaim_elf_sections_memory();
}

struct used_pages symtab_pages;
struct used_pages strtab_pages;
struct used_pages shstrtab_pages;
static unsigned long strtab_start, strtab_end = 0;
static unsigned long symtab_start, symtab_end = 0;

void elf_sections_reserve(struct multiboot_tag_elf_sections *__secs)
{
	auto secs = (multiboot_tag_elf_sections *) x86_placement_map((unsigned long) __secs);
	uint32_t num_secs = secs->num;
	Elf64_Shdr *sections = (Elf64_Shdr *)(__secs->sections);
	strtabs = (Elf64_Shdr *) x86_placement_map((unsigned long) &sections[secs->shndx]);

	shstrtab_pages.start = strtabs->sh_addr & ~(PAGE_SIZE - 1);
	shstrtab_pages.end = (uintptr_t) page_align_up((void *) (strtabs->sh_addr + strtabs->sh_size));
	page_add_used_pages(&shstrtab_pages);

	for(unsigned int i = 0; i < num_secs; i++)
	{
		Elf64_Shdr *section = (Elf64_Shdr *) x86_placement_map((unsigned long) (sections + i));
		Elf64_Word name = section->sh_name;

		strtab = (char*) x86_placement_map(strtabs->sh_addr);

		if(!strcmp(".symtab", elf_get_string(name)))
		{
			section = (Elf64_Shdr *) x86_placement_map((unsigned long) (sections + i));
			symtab_pages.start = section->sh_addr & ~(PAGE_SIZE - 1);
			symtab_pages.end = (uintptr_t) page_align_up((void *)(section->sh_size +
					   section->sh_addr));
			symtab_start = section->sh_addr;
			symtab_end = section->sh_addr + section->sh_size;

			symtab_pages.next = NULL;
			page_add_used_pages(&symtab_pages);
		}
		if(!strcmp(".strtab", elf_get_string(name)))
		{
			section = (Elf64_Shdr *) x86_placement_map((unsigned long) (sections + i));
			strtab_pages.start = section->sh_addr & ~(PAGE_SIZE - 1);
			strtab_pages.end = (uintptr_t) page_align_up((void *)(section->sh_size
					   + section->sh_addr));
			strtab_start = section->sh_addr;
			strtab_end = section->sh_addr + section->sh_size;
			strtab_pages.next = NULL;
			page_add_used_pages(&strtab_pages);
		}
	}
}

void reclaim_elf_sections_memory(void)
{
	if(strtab_start && strtab_end)
	{
		reclaim_pages(strtab_start, strtab_end);
	}

	if(symtab_start && symtab_end)
	{
		reclaim_pages(symtab_start, symtab_end);
	}
}
