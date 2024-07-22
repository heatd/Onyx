/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <string.h>

#include <onyx/fnv.h>
#include <onyx/symbol.h>

int setup_symbol(struct symbol *s, Elf64_Sym *sym, const char *name)
{
    s->name = strdup(name);
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
