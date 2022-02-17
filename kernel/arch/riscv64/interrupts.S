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
    ld sp, ABI_KERNEL_STACK_OFFSET(tp)
.else
    csrrw tp, sscratch, tp
.endif

    addi sp, sp, -280
    sd x1, 0(sp)


.if \user == 1
    # Fetch the stack from the percpu data
    ld x1, ABI_USER_STACK_OFFSET(tp)
    sd x1, 8(sp)
    csrrw tp, sscratch, tp
    sd tp, 24(sp)
    csrrw tp, sscratch, tp
.else
    addi x1, sp, 280
    sd x1, 8(sp)
    sd tp, 24(sp)
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
    # The stack and tp are restored later on
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

    # Disable interrupts for a little bit
    csrc sstatus, 1 << 1

    ld x31, 272(sp)
    andi x31, x31, 1 << 8
    bnez x31, 5f

    # Fill sscratch if we're returning to user space
    csrw sscratch, tp

5:
    ld x31, 240(sp)
    ld tp, 248(sp)
    csrw sepc, tp
    ld tp, 256(sp)
    csrw scause, tp
    ld tp, 264(sp)
    csrw stval, tp
    ld tp, 272(sp)
    csrw sstatus, tp
    ld tp, 24(sp)
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
    # The RISCV ABI says the stack must be 16 byte aligned in a procedure call
    andi sp, sp, -16
    call riscv_handle_trap
    # The stack (or new stack if we switched threads) is returned by riscv_handle_trap

    mv sp, a0

    RISCV_RESTORE_CONTEXT
    sret

/* extern "C" 
[[noreturn]]
void riscv_context_switch(thread *prev **%a0** , unsigned char *stack **%a1**, bool needs_to_kill_prev **%a2**);
*/
.global riscv_context_switch
.type riscv_context_switch, @function
riscv_context_switch:
	/* First thing to do: switch the sp */
	/* Then we can try to put the thread */
	mv sp, a1
    
	bnez a2, 2f 
1:
	RISCV_RESTORE_CONTEXT
    sret

2:
	/* note that prev is already in %rdi, no need to move it in */
	/* We also don't need to preserve any registers */
	mv s0, sp
    and sp, sp, -16
	call riscv_thread_put
	mv sp, s0
	j 1b

.global get_kernel_gp
.type get_kernel_gp,@function
get_kernel_gp:
.option push
.option norelax
    la a0, __global_pointer$
.option pop
    ret

.global platform_yield
.type platform_yield,@function
platform_yield:
.cfi_startproc
    csrr t0, sstatus
    andi t1, t0, 1 << 1
    or t0, t0, 1 << 8
    andi t0, t0, ~(1 << 1)
    beqz t1, 1f
    or t0, t0, 1 << 5
1:
    # Disable interrupts
    csrw sstatus, t0
    csrrw tp, sscratch, tp
    csrw sepc, ra
	/* Basically we need to set up an IRQ frame on the stack.
	 * For future reference consult include/onyx/registers.h
	*/
	RISCV_SAVE_CONTEXT 0
    mv a0, sp
    # The RISCV ABI says the stack must be 16 byte aligned in a procedure call
    andi sp, sp, -16
	call sched_schedule
	mv sp, a0
	RISCV_RESTORE_CONTEXT

	sret
.cfi_endproc

# extern "C" int return_from_execve(void *entry, void *stack)
.global return_from_execve
.type return_from_execve,@function
return_from_execve:
    # Disable interrupts
    csrci sstatus, 1 << 2
    csrw sepc, a0
    mv sp, a1

    csrw sscratch, tp

    # Zero registers
    # x2 is not zeroed since that's our sp, and x1 is used and zeroed down there after loading sstatus
    xor x3, x3, x3
    xor x4, x4, x4
    xor x5, x5, x5
    xor x6, x6, x6
    xor x7, x7, x7
    xor x8, x8, x8
    xor x9, x9, x9
    xor x10, x10, x10
    xor x11, x11, x11
    xor x12, x12, x12
    xor x13, x13, x13
    xor x14, x14, x14
    xor x15, x15, x15
    xor x16, x16, x16
    xor x17, x17, x17
    xor x18, x18, x18
    xor x19, x19, x19
    xor x20, x20, x20
    xor x21, x21, x21
    xor x22, x22, x22
    xor x23, x23, x23
    xor x24, x24, x24
    xor x25, x25, x25
    xor x26, x26, x26
    xor x27, x27, x27
    xor x28, x28, x28
    xor x29, x29, x29
    xor x30, x30, x30
    xor x31, x31, x31


    # Enable interrupts
    li x1, 1 << 5
    csrs sstatus, x1
    li x1, 1 << 8
    csrc sstatus, x1

    xor x1, x1, x1

    sret
