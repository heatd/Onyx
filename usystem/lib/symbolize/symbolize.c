/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include "include/symbolize/symbolize.h"

#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

// See demangle.cpp
char *demangle(const char *name, int *status);

static inline char *elf_get_string(Elf64_Word off, char *strtab)
{
    return strtab + off;
}

typedef uint32_t fnv_hash_t;

#define FNV_PRIME        16777619
#define FNV_OFFSET_BASIS 2166136261

static inline fnv_hash_t __fnv_hash(const uint8_t *data, size_t size)
{
    fnv_hash_t hash = FNV_OFFSET_BASIS;
    while (size--)
    {
        hash *= FNV_PRIME;
        hash ^= *data++;
    }

    return hash;
}

/* Used when continuing hashes (you'd call fnv_hash() and then call fnv_hash_cont
 * with the old hash as to continue hashing)
 */
__attribute__((unused)) static inline fnv_hash_t __fnv_hash_cont(const uint8_t *data, size_t size,
                                                                 fnv_hash_t hash)
{
    while (size--)
    {
        hash *= FNV_PRIME;
        hash ^= *data++;
    }

    return hash;
}

#define fnv_hash(data, size)            __fnv_hash((const uint8_t *) data, size)
#define fnv_hash_cont(data, size, hash) __fnv_hash_cont((const uint8_t *) data, size, hash)

static inline bool is_useful_symbol(Elf64_Sym *sym)
{
    if (sym->st_shndx == SHN_UNDEF || sym->st_shndx >= SHN_LORESERVE)
        return false;

    if (ELF64_ST_TYPE(sym->st_info) == STT_FILE || ELF64_ST_TYPE(sym->st_info) == STT_SECTION ||
        ELF64_ST_TYPE(sym->st_info) == STT_NOTYPE)
        return false;

    /* NOTE: We keep LOCAL symbols for debugging (i.e panic stack traces) */
    return true;
}

static int setup_symbol(struct symbol *s, Elf64_Sym *sym, const char *name)
{
    int st = 0;
    s->name = demangle(name, &st);
    if (st == -2)
        s->name = strdup(name);
    else
    {
        switch (st)
        {
            case -1:
                errno = ENOMEM;
                return -1;
            case -3:
                errno = EINVAL;
                return -3;
            case 0:
                break;
            default:
                return st;
        }
    }

    if (!s->name)
        return -1;

    s->name_hash = fnv_hash(s->name, strlen(s->name));

    s->value = sym->st_value;

    if (ELF64_ST_BIND(sym->st_info) & STB_GLOBAL)
        s->visibility |= SYMBOL_VIS_GLOBAL;

    if (ELF64_ST_BIND(sym->st_info) & STB_WEAK)
        s->visibility |= SYMBOL_VIS_WEAK;
#if DEBUG_SYMBOLS
    printk("Symbol: %s : Global: %s : Weak: %s : Value: %lx\n", s->name,
           s->visibility & SYMBOL_VIS_GLOBAL ? "y" : "n",
           s->visibility & SYMBOL_VIS_WEAK ? "y" : "n", s->value);
#endif

    if (ELF64_ST_TYPE(sym->st_info) & STT_FUNC)
        s->visibility |= SYMBOL_FUNCTION;
    else if (ELF64_ST_TYPE(sym->st_info) & STT_OBJECT)
        s->visibility |= SYMBOL_OBJECT;

    s->size = sym->st_size;

    return 0;
}

/**
 * @brief Frees the symbol table
 *
 * @param table Symbol table
 * @param syms Number of symbols
 */
void symbolize_free_symbols(struct symbol *table, size_t syms)
{
    for (size_t i = 0; i < syms; i++)
    {
        free(table[i].name);
    }

    free(table);
}

/**
 * @brief Symbolizes an executable/shared library/module
 *
 * @param fd File descriptor (must be mmap-able)
 * @param ctx Result (table of symbols)
 * @return 0 on success, negative error codes
 */
int symbolize_exec(int fd, struct symbolize_ctx *ctx)
{
    struct symbol *table;
    int st = 0;

    struct stat buf;

    if (fstat(fd, &buf) < 0)
        return -1;

    void *ptr = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED)
        return -1;

    Elf64_Ehdr *hdr = ptr;
    Elf64_Shdr *sections = (void *) ((char *) hdr + hdr->e_shoff);
    Elf64_Shdr *strtabs = &sections[hdr->e_shstrndx];
    Elf64_Shdr *symtab = NULL;
    char *shstrtab = (char *) (strtabs->sh_offset + (char *) ptr);

    char *strtab = NULL;

    for (unsigned int i = 0; i < hdr->e_shnum; i++)
    {
        char *name = elf_get_string(sections[i].sh_name, shstrtab);
        if (!strcmp(".symtab", name))
        {
            symtab = &sections[i];
        }
        else if (!strcmp(".strtab", name))
        {
            strtab = (char *) (sections[i].sh_offset + (char *) hdr);
        }
    }

    if (!strtab || !symtab)
    {
        st = -1;
        goto out;
    }

    const size_t num = symtab->sh_size / symtab->sh_entsize;
    Elf64_Sym *syms = (Elf64_Sym *) (symtab->sh_offset + (char *) hdr);
    size_t useful_syms = 0;

    for (size_t i = 0; i < num; i++)
    {
        Elf64_Sym *sym = &syms[i];
        if (!is_useful_symbol(sym))
            continue;

        useful_syms++;
    }

    table = calloc(sizeof(struct symbol), useful_syms);

    if (!table)
    {
        st = -1;
        goto out;
    }

    for (size_t i = 0, n = 0; i < num; i++)
    {
        Elf64_Sym *sym = &syms[i];
        if (!is_useful_symbol(sym))
            continue;

        struct symbol *s = &table[n];
        if (setup_symbol(s, sym, elf_get_string(sym->st_name, strtab)) < 0)
        {
            st = -1;
            goto out;
        }

        n++;
    }

    ctx->sym = table;
    ctx->nr_syms = useful_syms;

out:
    munmap(ptr, buf.st_size);
    if (st == -1 && table)
        symbolize_free_symbols(table, useful_syms);
    return st;
}

/**
 * @brief Gets the symbol of an address
 *
 * @param ctx Context
 * @param addr Address
 * @return Symbol that represents the address, or NULL
 */
struct symbol *symbolize_get_sym(struct symbolize_ctx *ctx, unsigned long addr)
{
    const size_t nr_syms = ctx->nr_syms;
    struct symbol *sym = NULL;

    long curdiff = LONG_MAX;

    for (size_t i = 0; i < nr_syms; i++)
    {
        struct symbol *s = &ctx->sym[i];

        /* Skip if it's not a function */
        if (!(s->visibility & SYMBOL_FUNCTION))
            continue;

        /* Check if it's inside the bounds of the symbol */

        if (!((unsigned long) addr >= s->value && (unsigned long) addr < s->value + s->size))
            continue;

        long diff = addr - s->value;

        /* If addr < symbol value, it can't be it */
        if (diff < 0)
            continue;
        else if (diff == 0)
        {
            /* Found it! This is the one! Return. */
            return s;
        }
        else
        {
            if (diff < curdiff)
            {
                curdiff = diff;
                sym = s;
            }
        }
    }

    return sym;
}

/**
 * @brief Symbolize an address
 *
 * @param ctx Context
 * @param addr Address
 * @param buf Buffer
 * @param buflen Length of the buffer
 * @return 0 on sucess, negative error code
 */
int symbolize_symbolize(struct symbolize_ctx *ctx, unsigned long addr, char *buf, size_t buflen)
{
    struct symbol *sym = symbolize_get_sym(ctx, addr);
    if (!sym)
        return errno = ENOENT, -1;

    long diff = addr - sym->value;
    int sprintf_ret;
    if (diff != 0)
        sprintf_ret = snprintf(buf, buflen, "%s+0x%lx", sym->name, diff);
    else
        sprintf_ret = snprintf(buf, buflen, "%s", sym->name);
    if (sprintf_ret < 0)
        return -1;
    if ((unsigned int) sprintf_ret >= buflen)
        return errno = E2BIG, -1;
    return 0;
}
