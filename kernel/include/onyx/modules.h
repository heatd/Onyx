/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_MODULES_H
#define _ONYX_MODULES_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <onyx/compiler.h>

#ifdef __cplusplus
#include <onyx/slice.hpp>
#endif

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

struct symbol;

#define SYMBOL_RESOLVE_MAY_BE_STATIC (1 << 0)

struct module_resolve_ctx
{
    const char *sym_name;
    bool success;
    struct symbol *sym;
    unsigned long flags;
    bool weak_sym;
};

extern struct module core_kernel;

int load_module(const char *path, const char *name);
void *module_allocate_pages(size_t size, int prot);
void module_dump(void);
void setup_core_kernel_module(void);
struct symbol *module_resolve_sym(const char *name);

struct file;

void *elf_load_kernel_module(struct file *file, struct module *module);
bool module_try_resolve(struct module *m, void *ctx);
void module_unmap(struct module *module);
void module_remove(struct module *m, bool unmap_sections);
void for_each_module(bool (*foreach_callback)(struct module *m, void *ctx), void *ctx);

__BEGIN_CDECLS
int sym_symbolize(void *address, char *buf, size_t bufsize, unsigned int flags);
int sym_get_off_size(unsigned long addr, unsigned long *off, unsigned long *size);
__END_CDECLS

#ifdef __cplusplus
static inline int sym_symbolize(void *address, cul::slice<char> buffer)
{
    return sym_symbolize(address, buffer.data(), buffer.size(), 0);
}
#endif

#define SYM_SYMBOLIZE_NO_OFFSET (1 << 0)

#define SYM_SYMBOLIZE_TRUNC    1
#define SYM_SYMBOLIZE_RAW_ADDR 2

// Recommended bufsize for sym_symbolize
#define SYM_SYMBOLIZE_BUFSIZ 150

#endif
