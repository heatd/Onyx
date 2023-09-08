/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_RISCV_PLATFORM_JUMP_LABEL_H
#define _ONYX_RISCV_PLATFORM_JUMP_LABEL_H

#include <onyx/compiler.h>
#include <onyx/types.h>

struct jump_label
{
    /* Note: We could compress some of these addresses down to 32-bit ints due to doing everything
     * relative to ip and/or -1UL on riscv (and near enough) */
    u64 ip;
    /* We stash the jump polarity in bit0 of key - this works because static keys have stronger
     * alignment than 1. */
    u64 key;
    s32 dest;
} __packed;

struct static_key;

#ifndef __clang__
#define __unlikely_branch __attribute__((cold))
#else
#define __unlikely_branch
#endif

/* Ok so - in theory, a jump and its target falling out of range (1MB both ways) is a problem.
 * In practice, it's not, as toolchains are careful and some really tip-toe when doing machine
 * function splitting (see LLVM rev D158647 for arm64). So we'll keep the AUIPC + JALR code, but
 * keep it disabled by default. This means more efficient codegen. If we ever need it, just enable
 * it.
 */
#ifdef RISCV_JUMP_LABEL_AUIPC_JALR
#define JUMP_LABEL_BRANCH_SIZE              8
#define RISCV_JUMP_LABEL_BRANCH_SEQ         "%=: .rept 2; ebreak; .endr\n"
#define RISCV_JUMP_LABEL_GOTO_EXTRA_CLOBBER , "t0" /* we may need t0 for auipc + jal codegen */
#else
#define JUMP_LABEL_BRANCH_SIZE      4
#define RISCV_JUMP_LABEL_BRANCH_SEQ "%=: ebreak\n"
#define RISCV_JUMP_LABEL_GOTO_EXTRA_CLOBBER
#endif

template <bool is_likely>
__always_inline bool jump_label_branch(struct static_key *key)
{
    __asm__ __volatile__ goto(".option push; .option norvc;\n" RISCV_JUMP_LABEL_BRANCH_SEQ
                              ".option pop\n"
                              ".pushsection .jump_label\n"
                              ".quad %=b\n"
                              ".quad %0 + %1\n"
                              ".long %2 - %=b\n"
                              ".popsection\n" ::"i"(key),
                              "i"(!is_likely)
                              : "memory" RISCV_JUMP_LABEL_GOTO_EXTRA_CLOBBER
                              : branch);
    return is_likely;
branch:
    __unlikely_branch;
    return !is_likely;
}

size_t jump_label_gen_branch(struct jump_label *label, unsigned char *buf);

__always_inline bool jump_label_polarity(struct jump_label *label)
{
    return label->key & 1;
}

__always_inline struct static_key *jump_label_key(struct jump_label *label)
{
    return (struct static_key *) (label->key & ~1);
}

#define JUMP_LABEL_JMP_IF_TRUE  (1)
#define JUMP_LABEL_JMP_IF_FALSE (0)

void jump_label_init();
void jump_label_patch_key(struct static_key *key);
void jump_label_patch_branch(struct static_key *key, bool en);

#define ARCH_HAS_JUMP_LABEL 1

#endif
