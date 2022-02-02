/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_X86_ALTERNATIVES_H
#define _ONYX_X86_ALTERNATIVES_H

// clang-format off
#define __ASM_ALTERNATIVE_INSTRUCTION(patch_func, size, priv1, priv2) \
    4096 :.fill size, 1, 0xcc;                                        \
    .pushsection .code_patch;                                          \
    .quad 4096b;                                                      \
    .quad size;                                                       \
    .quad patch_func;                                                 \
    .quad priv1;                                                      \
    .quad priv2;                                                      \
    .popsection;
// clang-format on
#ifndef __ASSEMBLER__

#include <onyx/utils.h>

struct code_patch_location
{
    void *address;
    unsigned long size;
    void (*patching_func)(struct code_patch_location *loc);
    void *priv[2];
} __attribute__((packed));

#define __ALTERNATIVE_INSTRUCTION(patch_func, size, priv1, priv2)                  \
    __asm__ __volatile__("4096: \n\t.fill " stringify(size) ", 1, 0xcc\n\t");      \
    __asm__ __volatile__(".pushsection .code_patch\n\t"                            \
                         ".quad 4096b\n\t"                                         \
                         ".quad " stringify(size) "\n\t"                           \
                                                  ".quad %c0\n\t"                  \
                                                  ".quad %c1\n\t"                  \
                                                  ".quad %c2\n\t"                  \
                                                  ".popsection" ::"i"(patch_func), \
                         "i"(priv1), "i"(priv2));

#ifdef __cplusplus
void x86_do_alternatives();
#endif

#endif

#endif
