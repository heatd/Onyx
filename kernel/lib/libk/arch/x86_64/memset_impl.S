/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#define RET ret
#define ALIGN_TEXT .p2align 4, 0x90

#ifndef L
#define L(label)	.L##label##\suffix
#endif

.macro memset_like suffix
    /* Test for 0 */
    test %rdx, %rdx
    jz L(out)

    /* Expand the value given into a 64-bit value */
    and	$0xff, %rsi
    mov	$0x0101010101010101, %rcx
    imul %rcx, %rsi

    /* Deal with [0..16], [16..32], [32..256] and [256..] separately */
    cmp $16, %rdx
    jbe L(0_to_16_bytes)

    cmp $32, %rdx
    jbe L(0_to_32_bytes)

    /* Heuristic tested on Kabylake R */
    /* The limit is likely much lower on FSRM but TODO */
    cmp $512, %rdx
    jae L(erms)

    /* Fallthrough to the 32 byte set */
    ALIGN_TEXT
L(32_byte_set):
    movq %rsi,   (%rdi)
    movq %rsi,   8(%rdi)
    movq %rsi,  16(%rdi)
    movq %rsi, 24(%rdi)
    /* We use both lea and arithmetic insns as to fully utilize execution units */
    lea 32(%rdi), %rdi
    sub $32, %rdx
    jz L(out)
    cmp $32, %rdx
    jae L(32_byte_set)

    /* Fallthrough to the 0..32 memset */
    ALIGN_TEXT
    /* This whole code (the part that handles the "tail") is based on being able to
     * do unaligned, overlapping stores. So something like (i.e 2-3 byte store):
     *          movw %sil, (%rdi)
     *          movw %sil, -2(%rdi, %rdx)
     * where rdi is dest, rsi is val, rdx is len. This is much cheaper than having a lot more branching
     * down with some duff's device-like thing.
     */
L(0_to_32_bytes):
    cmp $16, %rdx
    jbe L(0_to_16_bytes)
    movq %rsi, (%rdi)
    movq %rsi, 8(%rdi)
    movq %rsi, -16(%rdi, %rdx)
    movq %rsi,  -8(%rdi, %rdx)
    RET

    ALIGN_TEXT
L(0_to_16_bytes):
    cmp $8, %rdx
    jb L(4_to_7_bytes)
    movq %rsi,  (%rdi)
    movq %rsi, -8(%rdi, %rdx) 
    RET

    ALIGN_TEXT
L(4_to_7_bytes):
    cmp $4, %rdx
    jb L(1_to_3_bytes)
    movl %esi, (%rdi)
    movl %esi, -4(%rdi, %rdx)
    RET

    ALIGN_TEXT
L(1_to_3_bytes):
    cmp $1, %rdx
    je L(1_byte)
    movw %si, (%rdi)
    movw %si, -2(%rdi, %rdx)
    RET

L(1_byte):
    movb %sil, (%rdi)
    RET

    ALIGN_TEXT
L(erms):
    /* Note: We save rax temporarily in r8 since it's likely to be set up with a ret val */
    mov %rax, %r8
    mov %rsi, %rax
    mov %rdx, %rcx
    rep stosb
    mov %r8, %rax
L(out):
    RET

.endm
