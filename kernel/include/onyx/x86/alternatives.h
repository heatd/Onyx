/*
 * Copyright (c) 2021 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
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

#define PUSH_INSN(instr, feature)                       \
    ".long " stringify(feature) "\n"                    \
                                ".long 4098f - 4097f\n" \
                                "4097:" instr "\n"      \
                                "4098: \n"

#define END_ALT() \
    ".long -1\n"  \
    ".popsection\n"

/* clang-format off */
#define __GENERIC_ALTERNATIVE(old_instr, new_instr, feature) \
    "4096: " old_instr "\n" \
    ".pushsection .rodata.alternatives\n" \
    ".quad 4096b\n" \
    PUSH_INSN(old_instr, 0) \
    PUSH_INSN(new_instr, feature) \
    END_ALT()
/* clang-format on */

#define GENERIC_ALTERNATIVE(old, new, feature) \
    __asm__ __volatile__(__GENERIC_ALTERNATIVE(old, new, feature))

#define ALTERNATIVE_IO(old, new, feature, output, inputs...) \
    __asm__ __volatile__(__GENERIC_ALTERNATIVE(old, new, feature) : output : inputs)

#define ABI_CLOBBERS     "memory", "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"
#define ABI_CLOBBERS_1_1 "memory", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"

/* for alternatives that require clobbering every ABI register except one input and one output
 * register */
#define ALTERNATIVE_CALL_1_1(old, new, feature, output, inputs...) \
    __asm__ __volatile__(__GENERIC_ALTERNATIVE(old, new, feature)  \
                         : output                                  \
                         : inputs                                  \
                         : ABI_CLOBBERS_1_1)

#ifdef __cplusplus
void x86_do_alternatives();
#endif

#endif

#endif
