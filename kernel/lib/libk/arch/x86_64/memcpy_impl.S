/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/x86/asm.h>
#define ALIGN_TEXT .p2align 4, 0x90

#ifndef MEMCPY_SYM
#define MEMCPY_SYM memcpy
#endif

#ifndef MEMMOVE_SYM
#define MEMMOVE_SYM memmove
#endif

#ifndef L
#define L(label)	.L##label##\suffix
#endif

/* Ugh. COPYINOUT is defined for copy_to/from_user */
#ifdef COPYINOUT
#define COPYINOUTARG from_user
#endif

#ifndef MEMCPY_RET
#define MRET RET
#else
#define MRET MEMCPY_RET
#endif

.macro memcpy_like overlap suffix COPYINOUTARG
    /* Test for 0 */
    test %rdx, %rdx
    jz L(out)

    /* Deal with [0..16], [16..32], [32..256] and [256..] separately */
    cmp $16, %rdx
    jbe L(0_to_16_bytes)

    cmp $32, %rdx
    jbe L(0_to_32_bytes)

.if \overlap == 1
    /* If src < dst and they overlap, do a backwards copy */
    mov %rdi, %r8
    sub %rsi, %r8
    cmp %rdx, %r8
    jb L(copy_backwards)
.endif

    /* Heuristic tested on Kabylake R */
    /* The limit is likely much lower on FSRM but TODO */
    cmp $512, %rdx
    jae L(erms)

    /* Fallthrough to the 32 byte copy */
    ALIGN_TEXT
L(32_byte_copy):
0:  movq  (%rsi), %rcx
1:  movq  8(%rsi), %r8
2:  movq 16(%rsi), %r9
3:  movq 24(%rsi), %r10
64:  movq %rcx,   (%rdi)
65:  movq %r8,   8(%rdi)
66:  movq %r9,  16(%rdi)
67:  movq %r10, 24(%rdi)
    /* We use both lea and arithmetic insns as to fully utilize execution units */
    lea 32(%rsi), %rsi
    lea 32(%rdi), %rdi
    sub $32, %rdx
    jz L(out)
    cmp $32, %rdx
    jae L(32_byte_copy)

    /* Fallthrough to the 0..32 copy */
    ALIGN_TEXT
    /* This whole code (the part that handles the "tail") is based on being able to
     * do unaligned, overlapping loads and stores. So something like (i.e 2-3 byte copy):
     *          movzwl (%rsi), %ecx
     *          movzwl -2(%rsi, %rdx), %r8d
     *          movw %cx, (%rdi)
     *          movw %r8w, -2(%rdi, %rdx)
     * where rdi is dest, rsi is src, rdx is len. This is much cheaper than having a lot more branching
     * down with some duff's device-like thing.
     *
     * Worth noting that tail code doesn't need a special backwards version as we load everything
     * and only then store everything.
     */
L(0_to_32_bytes):
    cmp $16, %rdx
    jbe L(0_to_16_bytes)
4:  movq  (%rsi), %rcx
5:  movq 8(%rsi), %r8
6:  movq -16(%rsi, %rdx), %r9
7:  movq -8(%rsi, %rdx), %r10
68: movq %rcx, (%rdi)
69: movq %r8, 8(%rdi)
70: movq %r9, -16(%rdi, %rdx)
71: movq %r10,  -8(%rdi, %rdx)
    MRET

    ALIGN_TEXT
L(0_to_16_bytes):
    cmp $8, %rdx
    jb L(4_to_7_bytes)
8:  movq   (%rsi), %rcx
9:  movq -8(%rsi, %rdx), %r8
72: movq %rcx,  (%rdi)
73: movq %r8, -8(%rdi, %rdx) 
    MRET

    ALIGN_TEXT
L(4_to_7_bytes):
    cmp $4, %rdx
    jb L(1_to_3_bytes)
10: movl (%rsi), %ecx
11: movl -4(%rsi, %rdx), %r8d
74: movl %ecx, (%rdi)
75: movl %r8d, -4(%rdi, %rdx)
    MRET

    ALIGN_TEXT
L(1_to_3_bytes):
    /* Note: We use movz(b,w)l as it's superior to doing a load to a partial register */
    cmp $1, %rdx
    je L(1_byte)
12: movzwl (%rsi), %ecx
13: movzwl -2(%rsi, %rdx), %r8d
76: movw %cx, (%rdi)
77: movw %r8w, -2(%rdi, %rdx)
    MRET

L(1_byte):
14: movzbl (%rsi), %ecx
78: movb %cl, (%rdi)
    MRET

    ALIGN_TEXT
L(erms):
    mov %rdx, %rcx
99: rep movsb
L(out):
    MRET

.if \overlap == 1
L(copy_backwards):
    lea (%rdi, %rdx), %rdi
    lea (%rsi, %rdx), %rsi
    ALIGN_TEXT
    /* Standard 32-byte copy loop, as above, but backwards */
L(32b_backwards):
    movq  -8(%rsi), %rcx
    movq -16(%rsi), %r8
    movq -24(%rsi), %r9
    movq -32(%rsi), %r10
    movq %rcx,  -8(%rdi)
    movq %r8,  -16(%rdi)
    movq %r9,  -24(%rdi)
    movq %r10, -32(%rdi)
    /* We use both lea and arithmetic insns as to fully utilize execution units */
    lea -32(%rsi), %rsi
    lea -32(%rdi), %rdi
    sub $32, %rdx
    jz L(out)
    cmp $32, %rdx
    jae L(32b_backwards)

    /* Do tail, but re-adjust regs */
    sub %rdx, %rdi
    sub %rdx, %rsi
    jmp L(0_to_32_bytes)
.endif

#ifdef COPYINOUT
#define EHTAB(fault_label, fault_out) \
.quad fault_label; .quad fault_out;

.pushsection .ehtable
.if \from_user == 1
EHTAB(0b, L(fault_out))
EHTAB(1b, L(fault_out))
EHTAB(2b, L(fault_out))
EHTAB(3b, L(fault_out))
EHTAB(4b, L(fault_out))
EHTAB(5b, L(fault_out))
EHTAB(6b, L(fault_out))
EHTAB(7b, L(fault_out))
EHTAB(8b, L(fault_out))
EHTAB(9b, L(fault_out))
EHTAB(10b, L(fault_out))
EHTAB(11b, L(fault_out))
EHTAB(12b, L(fault_out))
EHTAB(13b, L(fault_out))
EHTAB(14b, L(fault_out))
.else
EHTAB(64b, L(fault_out))
EHTAB(65b, L(fault_out))
EHTAB(66b, L(fault_out))
EHTAB(67b, L(fault_out))
EHTAB(68b, L(fault_out))
EHTAB(69b, L(fault_out))
EHTAB(70b, L(fault_out))
EHTAB(71b, L(fault_out))
EHTAB(72b, L(fault_out))
EHTAB(73b, L(fault_out))
EHTAB(74b, L(fault_out))
EHTAB(75b, L(fault_out))
EHTAB(76b, L(fault_out))
EHTAB(77b, L(fault_out))
EHTAB(78b, L(fault_out))
.endif
EHTAB(99b, L(fault_out))
.popsection
#endif

.endm
