/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/internal_abi.h>

.macro RISCV_SAVE_CONTEXT user
.if \user == 1
    sd sp, ABI_USER_STACK_OFFSET(tp)
    ld sp, ABI_KERNEL_STACK_OFFSET(sp)
.endif
    addi sp, sp, -280
    sd x1, 0(sp)
    csrrw tp, sscratch, tp


.if \user == 1
    # Fetch the stack from the percpu data
    ld x1, ABI_USER_STACK_OFFSET(tp)
    sd x1, 8(sp)
.else
    addi x1, sp, 280
    sd x1, 8(sp)
.endif

    sd x3, 16(sp)
    sd x5, 32(sp)
    sd x6, 40(sp)
    sd x7, 48(sp)
    sd x8, 56(sp)
    sd x9, 64(sp)
    sd x10, 72(sp)
    sd x11, 80(sp)
    sd x12, 88(sp)
    sd x13, 96(sp)
    sd x14, 104(sp)
    sd x15, 112(sp)
    sd x16, 120(sp)
    sd x17, 128(sp)
    sd x18, 136(sp)
    sd x19, 144(sp)
    sd x20, 152(sp)
    sd x21, 160(sp)
    sd x22, 168(sp)
    sd x23, 176(sp)
    sd x24, 184(sp)
    sd x25, 192(sp)
    sd x26, 200(sp)
    sd x27, 208(sp)
    sd x28, 216(sp)
    sd x29, 224(sp)
    sd x30, 232(sp)
    sd x31, 240(sp)

    # Zero-out scratch when entering the kernel
    csrw sscratch, zero
    sd tp, 24(sp)

    csrr a0, sepc
    sd a0, 248(sp)
    csrr a0, scause
    sd a0, 256(sp)
    csrr a0, stval
    sd a0, 264(sp)
    csrr a0, sstatus
    sd a0, 272(sp)
.endm

.macro RISCV_RESTORE_CONTEXT
    ld x1, 0(sp)
    # The stack is restored later on
    ld x3, 16(sp)
    ld x5, 32(sp)
    ld x6, 40(sp)
    ld x7, 48(sp)
    ld x8, 56(sp)
    ld x9, 64(sp)
    ld x10, 72(sp)
    ld x11, 80(sp)
    ld x12, 88(sp)
    ld x13, 96(sp)
    ld x14, 104(sp)
    ld x15, 112(sp)
    ld x16, 120(sp)
    ld x17, 128(sp)
    ld x18, 136(sp)
    ld x19, 144(sp)
    ld x20, 152(sp)
    ld x21, 160(sp)
    ld x22, 168(sp)
    ld x23, 176(sp)
    ld x24, 184(sp)
    ld x25, 192(sp)
    ld x26, 200(sp)
    ld x27, 208(sp)
    ld x28, 216(sp)
    ld x29, 224(sp)
    ld x30, 232(sp)
    ld x31, 240(sp)

    ld a0, 248(sp)
    csrw sepc, a0
    ld a0, 256(sp)
    csrw scause, a0
    ld a0, 264(sp)
    csrw stval, a0
    ld a0, 272(sp)
    csrw sstatus, a0
    ld x4, 24(sp)
    ld sp, 8(sp)
.endm

.balign 4
.global riscv_trap_entry
riscv_trap_entry:
    # sscratch is used to save the thread pointer when in user-space
    # If we're not in user-space, sscratch is 0
    csrrw tp, sscratch, tp
 
    bnez tp, 1f
    # Arrived from kernel mode
    RISCV_SAVE_CONTEXT 0
    j 2f
1:
    # Arrived from user mode
    RISCV_SAVE_CONTEXT 1
2:
    # Reload the global pointer because we may need it
.option push
.option norelax
    la gp, __global_pointer$
.option pop
    mv a0, sp
    mv s0, sp # So we can restore the stack after the call (to unalign it)
    # The RISCV ABI says the stack must be 16 byte aligned in a procedure call
    andi sp, sp, -16
    call riscv_handle_trap

    # We have saved the sp on s0, so use it to restore the stack (so we can properly unwind it)
    mv sp, s0

    RISCV_RESTORE_CONTEXT
    sret
