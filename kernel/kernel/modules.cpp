/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/cred.h>
#include <onyx/elf.h>
#include <onyx/file.h>
#include <onyx/init.h>
#include <onyx/modules.h>
#include <onyx/symbol.h>
#include <onyx/user.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

bool mods_disabled = 0;
#define DEFAULT_SIZE 100

extern char _text_start;
extern char _text_end;
extern char _data_start;
extern char _data_end;
extern char _ro_start;
extern char _ro_end;

struct module core_kernel;

static struct spinlock module_list_lock;
static struct module *module_list = NULL;
static struct module *tail = NULL;

void for_each_module(bool (*foreach_callback)(struct module *m, void *ctx), void *ctx)
{
    spin_lock(&module_list_lock);

    struct module *m = module_list;

    while (m)
    {
        if (!foreach_callback(m, ctx))
            break;
        m = m->next;
    }

    spin_unlock(&module_list_lock);
}

void module_add(struct module *mod)
{
    spin_lock(&module_list_lock);

    if (!module_list)
    {
        module_list = tail = mod;
    }
    else
    {
        tail->next = mod;
        mod->prev = tail;
        tail = mod;
    }

    spin_unlock(&module_list_lock);
}

void module_remove_from_list(struct module *mod)
{
    spin_lock(&module_list_lock);

    if (mod->prev)
        mod->prev->next = mod->next;
    else
        module_list = mod->next;

    if (mod->next)
        mod->next->prev = mod->prev;
    else
        tail = mod->prev;

    spin_unlock(&module_list_lock);
}

void setup_core_kernel_module(void)
{
    core_kernel.name = "<kernel>";
    core_kernel.layout.start_text = (unsigned long) &_text_start;
    core_kernel.layout.start_data = (unsigned long) &_data_start;
    core_kernel.layout.start_ro = (unsigned long) &_ro_start;
    core_kernel.layout.text_size = (uintptr_t) &_text_end - (uintptr_t) &_text_start;
    core_kernel.layout.data_size = (uintptr_t) &_data_end - (uintptr_t) &_data_start;
    core_kernel.layout.ro_size = (uintptr_t) &_ro_end - (uintptr_t) &_ro_start;
    core_kernel.layout.base = KERNEL_VIRTUAL_BASE;
    core_kernel.path = "/vmonyx";

    setup_kernel_symbols(&core_kernel);

    module_add(&core_kernel);
}

INIT_LEVEL_VERY_EARLY_CORE_ENTRY(setup_core_kernel_module);

bool symbol_is_exported(struct symbol *s)
{
    if (!(s->visibility & SYMBOL_VIS_GLOBAL))
        return false;
    return true;
}

bool module_try_resolve(struct module *m, void *ctx)
{
    struct module_resolve_ctx *c = (module_resolve_ctx *) ctx;

    fnv_hash_t hash = fnv_hash(c->sym_name, strlen(c->sym_name));

    for (size_t i = 0; i < m->nr_symtable_entries; i++)
    {
        struct symbol *s = &m->symtable[i];

        if (s->name_hash == hash && !strcmp(s->name, c->sym_name))
        {
            if (!symbol_is_exported(s) && !(c->flags & SYMBOL_RESOLVE_MAY_BE_STATIC))
                return true;
            bool is_weak = s->visibility & SYMBOL_VIS_WEAK;

            c->weak_sym = is_weak;
            c->success = true;
            c->sym = s;

            return true;
        }
    }

    return true;
}

struct symbol *module_resolve_sym(const char *name)
{
    struct module_resolve_ctx ctx = {};
    ctx.sym_name = name;
    ctx.success = false;
    ctx.sym = NULL;

    for_each_module(module_try_resolve, &ctx);

    if (ctx.success)
        return ctx.sym;
    return NULL;
}

void module_unmap(struct module *module)
{
    if (module->layout.start_text)
    {
        vm_munmap(&kernel_address_space, (void *) module->layout.start_text,
                  module->layout.text_size);
    }

    if (module->layout.start_ro)
    {
        vm_munmap(&kernel_address_space, (void *) module->layout.start_ro, module->layout.ro_size);
    }

    if (module->layout.start_data)
    {
        vm_munmap(&kernel_address_space, (void *) module->layout.start_data,
                  module->layout.data_size);
    }
}

void module_remove(struct module *m, bool unmap_sections)
{
    if (m->symtable)
        free(m->symtable);
    if (m->path)
        free((char *) m->path);
    if (m->name)
        free((char *) m->name);

    if (unmap_sections)
        module_unmap(m);

    module_remove_from_list(m);

    free(m);
}

int load_module(const char *path, const char *name)
{
    struct file *file = NULL;
    struct module *mod = (module *) zalloc(sizeof(struct module));
    if (!mod)
        return -1;
    void *entry = nullptr;
    module_init_t init = nullptr;

    if (!(mod->path = strdup(path)))
        goto error_path;

    if (!(mod->name = strdup(name)))
        goto error_path;

    module_add(mod);

    file = open_vfs(get_fs_root(), path);
    if (!file)
    {
        errno = ENOENT;
        goto error_path;
    }

    entry = elf_load_kernel_module(file, mod);
    if (!entry)
    {
        goto error_path;
    }

    init = (module_init_t) entry;

    /* TODO: Should we remove the module if init() < 0? */
    init();

    /* Release used resources */
    fd_put(file);

    return 0;

error_path:
    if (file)
        fd_put(file);
    module_remove(mod, true);

    return -errno;
}

void *module_allocate_pages(size_t size, int prot)
{
    size_t pages = vm_size_to_pages(size);

    void *p = vmalloc(pages, VM_TYPE_MODULE, prot);
    return p;
}

struct common_block
{
    const char *symbol;
    void *buf;
    size_t size;
    struct common_block *next;
};

struct common_block *blocks = NULL;

/* TODO: Common blocks are badly implemented and they leak because the
 * struct module never owns them
 */

uintptr_t get_common_block(const char *name, size_t size)
{
    struct common_block *h = blocks;

    for (; h != NULL; h = h->next)
    {
        if (!strcmp(h->symbol, name))
            return (uintptr_t) h->buf;
    }

    struct common_block *b = (common_block *) zalloc(sizeof(struct common_block));
    if (!b)
        return 0;

    b->symbol = strdup(name);
    b->buf = module_allocate_pages(size, VM_WRITE);
    b->size = size;

    struct common_block **i = &blocks;

    while (*i)
        i = &(*i)->next;
    *i = b;

    return (uintptr_t) b->buf;
}

int sys_insmod(const char *path, const char *name)
{
    int st = 0;
    const char *kpath = NULL;
    const char *kname = NULL;
    struct creds *c = creds_get();

    if (c->euid != 0)
        return -EPERM;
    kpath = strcpy_from_user(path);
    if (!kpath)
    {
        st = -errno;
        goto out;
    }

    kname = strcpy_from_user(name);
    if (!kname)
    {
        st = -errno;
        goto out;
    }

    st = load_module(kpath, kname);

    if (st < 0)
        st = -errno;
out:
    free((char *) kpath);
    free((char *) kname);
    creds_put(c);
    return st;
}

static bool module_dump_each(struct module *m, void *ctx)
{
    const char *name = m->name;
    unsigned long start_text = m->layout.start_text;
    unsigned long start_ro = m->layout.start_ro;
    unsigned long start_data = m->layout.start_data;
    unsigned long end_text = start_text + m->layout.text_size;
    unsigned long end_ro = start_ro + m->layout.ro_size;
    unsigned long end_data = start_data + m->layout.data_size;

    printk("Module %s - .text (%lx - %lx), .rodata (%lx - %lx), .data(%lx - %lx)\n", name,
           start_text, end_text, start_ro, end_ro, start_data, end_data);

    return true;
}

void module_dump(void)
{
    for_each_module(module_dump_each, NULL);
}
