/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_MODULES_H
#define _KERNEL_MODULES_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <onyx/elf.h>

struct module_layout
{
	unsigned long base;
	unsigned long start_text;
	unsigned long text_size;
	unsigned long start_data;
	unsigned long data_size;
	unsigned long start_ro;
	unsigned long ro_size;
};

typedef int (*module_init_t)(void);
typedef int (*module_fini_t)(void);

struct module
{
	const char *path;
	const char *name;
	struct module_layout layout;
	size_t size;
	struct module *prev, *next;
	size_t nr_symtable_entries;
	struct symbol *symtable;
	module_fini_t fini;
};

struct module_resolve_ctx
{
	const char *sym_name;
	bool success;
	unsigned long retval;
	bool weak_sym;
};


extern struct module core_kernel;

int load_module(const char *path, const char *name);
void *module_allocate_pages(size_t size, int prot);
void module_dump(void);
void setup_core_kernel_module(void);
unsigned long module_resolve_sym(const char *name);
void *elf_load_kernel_module(void *file, struct module *module);
bool module_try_resolve(struct module *m, void *ctx);
void module_unmap(struct module *module);
void module_remove(struct module *m, bool unmap_sections);
void for_each_module(bool (*foreach_callback)(struct module *m, void *ctx), void *ctx);

#endif
