/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef SYMBOLIZE_H
#define SYMBOLIZE_H

#include <stddef.h>
#include <stdint.h>

struct symbol
{
    char *name;
    uint32_t name_hash;
    unsigned long value;
    unsigned long size;
    uint8_t visibility;
};

#define SYMBOL_VIS_LOCAL  0
#define SYMBOL_VIS_GLOBAL 1
#define SYMBOL_VIS_WEAK   (1 << 1)
#define SYMBOL_FUNCTION   (1 << 2)
#define SYMBOL_OBJECT     (1 << 3)

struct symbolize_ctx
{
    struct symbol *sym;
    size_t nr_syms;
};

/**
 * @brief Symbolizes an executable/shared library/module
 *
 * @param fd File descriptor (must be mmap-able)
 * @param ctx Result (table of symbols)
 * @return 0 on success, negative error codes
 */
int symbolize_exec(int fd, struct symbolize_ctx *ctx);

/**
 * @brief Frees the symbol table
 *
 * @param table Symbol table
 * @param syms Number of symbols
 */
void symbolize_free_symbols(struct symbol *table, size_t syms);

/**
 * @brief Gets the symbol of an address
 *
 * @param ctx Context
 * @param addr Address
 * @return Symbol that represents the address, or NULL
 */
struct symbol *symbolize_get_sym(struct symbolize_ctx *ctx, unsigned long addr);

/**
 * @brief Symbolize an address
 *
 * @param ctx Context
 * @param addr Address
 * @param buf Buffer
 * @param buflen Length of the buffer
 * @return 0 on sucess, negative error code
 */
int symbolize_symbolize(struct symbolize_ctx *ctx, unsigned long addr, char *buf, size_t buflen);

#endif
