/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

.section .text

#define STRUCT_REGS_SIZE 272

.macro save_regs el
    sub sp, sp, #32
    stp x28, x29, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x24, x25, [sp, #-16]!
    stp x22, x23, [sp, #-16]!
    stp x20, x21, [sp, #-16]!
    stp x18, x19, [sp, #-16]!
    stp x16, x17, [sp, #-16]!
    stp x14, x15, [sp, #-16]!
    stp x12, x13, [sp, #-16]!
    stp x10, x11, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x0, x1, [sp, #-16]!

.if \el == 0
    mrs x0, sp_el0
.else
    add x0, sp, #STRUCT_REGS_SIZE
.endif
    mrs x1, elr_el1
    mrs x2, spsr_el1

    stp x30, x0, [sp, #240]
    stp x1, x2, [sp, #256]
.endm

.macro restore_regs el
    ldp x30, x0, [sp, #240]
    ldp x1, x2, [sp, #256]
.if \el == 0
    msr sp_el0, x0
.endif
    msr elr_el1, x1
    msr spsr_el1, x2

    ldp x0, x1, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x10, x11, [sp], #16
    ldp x12, x13, [sp], #16
    ldp x14, x15, [sp], #16
    ldp x16, x17, [sp], #16
    ldp x18, x19, [sp], #16
    ldp x20, x21, [sp], #16
    ldp x22, x23, [sp], #16
    ldp x24, x25, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x28, x29, [sp], #16

    add sp, sp, #32
.endm

.global arm64_exception_vector_table
.balign 0x800
arm64_exception_vector_table:
curr_el_sp0_sync:
    save_regs 1
    mov x0, sp
    bl arm64_exception_sync
    b arm64_exception_out_el1
.balign 0x80
curr_el_sp0_irq:
    save_regs 1
    mov x0, sp
    bl arm64_exception_irq
    b arm64_exception_out_el1
.balign 0x80
curr_el_sp0_fiq:
    save_regs 1
    mov x0, sp
    bl arm64_exception_fiq
    b arm64_exception_out_el1
.balign 0x80
curr_el_sp0_serror:
    save_regs 1
    mov x0, sp
    bl arm64_exception_serror
    b arm64_exception_out_el1
.balign 0x80
curr_el_spx_sync:
    save_regs 1
    mov x0, sp
    bl arm64_exception_sync
    b arm64_exception_out_el1
.balign 0x80
curr_el_spx_irq:
    save_regs 1
    mov x0, sp
    bl arm64_exception_irq
    b arm64_exception_out_el1
.balign 0x80
curr_el_spx_fiq:
    save_regs 1
    mov x0, sp
    bl arm64_exception_fiq
    b arm64_exception_out_el1
.balign 0x80
curr_el_spx_serror:
    save_regs 1
    mov x0, sp
    bl arm64_exception_serror
    b arm64_exception_out_el1
.balign 0x80
lower_el_a64_spx_sync:
    save_regs 0
    mov x0, sp
    bl arm64_exception_sync
    b arm64_exception_out_el0
.balign 0x80
lower_el_a64_spx_irq:
    save_regs 0
    mov x0, sp
    bl arm64_exception_irq
    b arm64_exception_out_el0
.balign 0x80
lower_el_a64_spx_fiq:
    save_regs 0
    mov x0, sp
    bl arm64_exception_fiq
    b arm64_exception_out_el0
.balign 0x80
lower_el_a64_spx_serror:
    save_regs 0
    mov x0, sp
    bl arm64_exception_serror
    b arm64_exception_out_el0
lower_el_a32_spx_sync:
    save_regs 0
    mov x0, sp
    bl arm64_exception_sync
    b arm64_exception_out_el0
.balign 0x80
lower_el_a32_spx_irq:
    save_regs 0
    mov x0, sp
    bl arm64_exception_irq
    b arm64_exception_out_el0
.balign 0x80
lower_el_a32_spx_fiq:
    save_regs 0
    mov x0, sp
    bl arm64_exception_fiq
    b arm64_exception_out_el0
.balign 0x80
lower_el_a32_spx_serror:
    save_regs 0
    mov x0, sp
    bl arm64_exception_serror
    b arm64_exception_out_el0

.balign 16
arm64_exception_out_el1:
    restore_regs 1
    eret
.balign 16
arm64_exception_out_el0:
    restore_regs 0
    eret
