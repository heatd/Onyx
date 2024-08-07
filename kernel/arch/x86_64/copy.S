/*
 * Copyright (c) 2018 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
.section .text

#include <onyx/x86/asm.h>

.global __copy_non_temporal
.type __copy_non_temporal, @function
# __copy_non_temporal assumes that the buffers are properly aligned for the copy
# Failure to do so will result in worse performance
# __copy_non_temporal also assumes that the byte count is also aligned

# RDI holds destination buffer
# RSI holds source buffer
# RDX holds byte count
__copy_non_temporal:
    prefetchnta (%rsi)

.loop:
    mov (%rsi), %rax
    movnti %rax, (%rdi)
    add $8, %rdi
    add $8, %rsi
    sub $8, %rdx

    jnz .loop

    xor %rax, %rax

    RET

.global __set_non_temporal
.type __set_non_temporal, @function
# __set_non_temporal assumes that the buffer is properly aligned for the memset
# Failure to do so will result in worse performance
# __set_non_temporal also assumes that the byte count is also aligned

# RDI holds destination buffer
# RSI holds byte value
# RDX holds byte count
__set_non_temporal:

    # Since the byte value is probably not set up like we want it to,
    # fill the register using the byte, so we can copy 8 bytes at a time

    # Byte 0
    mov %rsi, %r8
    and $0xff, %r8
    mov %r8, %rax
    # Byte 1
    shl $8, %r8
    or %r8, %rax
    # Byte 2
    shl $8, %r8
    or %r8, %rax
    # Byte 3
    shl $8, %r8
    or %r8, %rax
    # Byte 4
    shl $8, %r8
    or %r8, %rax
    # Byte 5
    shl $8, %r8
    or %r8, %rax
    # Byte 6
    shl $8, %r8
    or %r8, %rax
    # Byte 7
    shl $8, %r8
    or %r8, %rax

.L0:
    movnti %rax, (%rdi)
    add $8, %rdi
    sub $8, %rdx

    jnz .L0

    xor %rax, %rax

    RET
