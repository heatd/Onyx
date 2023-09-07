/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_X86_PLATFORM_JUMP_LABEL_H
#define _ONYX_X86_PLATFORM_JUMP_LABEL_H

#include <onyx/compiler.h>
#include <onyx/types.h>

struct jump_label
{
    /* Note: We could compress some of these addresses down to 32-bit ints due to doing everything
     * relative to ip and/or -1UL on x86 (and near enough) */
    u64 ip;
    /* We stash the jump polarity in bit0 of key - this works because static keys have stronger
     * alignment than 1. */
    u64 key;
    s32 dest;
} __packed;

struct static_key;

template <bool is_likely>
__always_inline bool jump_label_branch(struct static_key *key)
{
    __asm__ __volatile__ goto("%=: .rept 5; int3; .endr\n"
                              ".pushsection .jump_label\n"
                              ".quad %=b\n"
                              ".quad %c0 + %c1\n"
                              ".long %2 - %=b\n"
                              ".popsection\n" ::"i"(key),
                              "i"(!is_likely)
                              : "memory"
                              : branch);
    return is_likely;
branch:
    return !is_likely;
}

#define JUMP_LABEL_BRANCH_SIZE 5

__always_inline size_t jump_label_gen_branch(struct jump_label *label, unsigned char *buf)
{
    s32 diff = label->dest;

    if (diff + 2 <= 127 && diff + 2 > -128)
    {
        // Fits in a 2-byte jmp imm8
        buf[0] = 0xeb;
        buf[1] = diff - 2;
        return 2;
    }
    else
    {
        // 5-byte jmp imm32
        buf[0] = 0xe9;
        diff -= 5;
        __builtin_memcpy(&buf[1], &diff, sizeof(s32));
        return 5;
    }
}

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
