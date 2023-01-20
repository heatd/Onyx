/*
 * Copyright (c) 2018 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <platform/syscall.h>
#include <onyx/x86/asm.h>

/* Everything here is permanently mapped */
.section .text.x86_entry

# Syscall ABI details:
# Arguments are passed on %rdi, %rsi, %rdx, %r10, %r8 and %r9
# Syscall number passed in %rax
# Return address is stored in %rcx by the syscall instruction
# RFLAGS stored in r11
# Registers %rbx, %rsp, %rbp, %r12-15 are preserved
# Registers %rax, %rcx, %r11 are clobbered

.macro SAVE_PRESERVED_SYSCALL_REGS
    # First get the user stack
    mov %gs:scratch_rsp, %r11

    # Then push the user %rsp
    push %r11

    # Now everything else
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
.endm

.macro RESTORE_PRESERVED_SYSCALL_REGS
    # Undo what we did before
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx

    pop %rdi

.endm

.macro CLEAR_CLOBBERED_REGS_EXCEPT_RAX_SYSCALL_RDI
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %r8, %r8
    xor %r9, %r9
    xor %r10, %r10
.endm

.macro popaq
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rsi
    pop %rdi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
.endm

#define REGISTERS_UNUSED_OFF		16
#define KERNEL_DS		0x10

.global syscall_ENTRY64
.align 64
.type syscall_ENTRY64,@function
syscall_ENTRY64:

    .cfi_startproc
    .cfi_register rip, rcx
    .cfi_return_column rcx
    .cfi_def_cfa_register rsp
    .cfi_def_cfa_offset 0

    cld
    swapgs

    # We can't preempt right now(unless we want chaos)!
    # Get the kernel stack, and save the user-stack
    mov %rsp, %gs:scratch_rsp
    mov %gs:kernel_stack, %rsp

    # Save %rcx and %r11, since they're needed for sysret
    push %rcx
    push %r11
    
    # Set up the syscall frame
    push %rax
    push %rdi
    push %rsi
    push %rdx
    push %r10
    push %r8
    push %r9

    # Save the preserved registers
    SAVE_PRESERVED_SYSCALL_REGS

    sti

    # End the stack frame list
    xor %rbp, %rbp

    # Ah, we've saved the registers, and the user stack is safe - we can
    # continue now (possible to preempt)
    # Save the old segments, and switch to the kernel ones

    mov %ds, %ecx
    push %rcx
    mov $KERNEL_DS, %cx
    mov %cx, %ds
    mov %cx, %es

    mov %rsp, %rdi

    call do_syscall64

    
    # Save our registers for the signal_is_pending call
    mov %rax, %rdi
    push %rdi
    mov %rsp, %rsi
    
    # Adjust %rsi so it actually points to the stack
    # (since the ret val got pushed)
    add $8, %rsi
    push %rsi

    call signal_is_pending

    cmp $1, %al

    je syscall_signal_path

    # If we didn't take the signal branch, restore the stack and pop the retval back
    add $8, %rsp
    pop %rax

    pop %rcx
    mov %cx, %ds
    mov %cx, %es

    RESTORE_PRESERVED_SYSCALL_REGS

    # and restore the other regs
    pop %r9
    pop %r8
    pop %r10
    pop %rdx
    pop %rsi

    # Disable the interrupts since we're about to do some naughty stuff with the stack
    cli

    # Save the user rsp really quickly, since no one will touch the stack
    push %rdi
    add $8, %rsp
    # Pop the real %rdi
    pop %rdi

    # Skip %rax
    add $8, %rsp

    # Restore r11 + rcx for sysret
    pop %r11
    pop %rcx

    # Now get the stack
    mov -40(%rsp), %rsp
    # and finally, swap back to the user gs
    swapgs

    sysretq

#define STRUCT_REGISTERS_SIZE		(23 * 8)

syscall_signal_path:
    pop %rsi
    pop %rdi
    sub $STRUCT_REGISTERS_SIZE, %rsp
    mov %rsp, %rdx
    call do_signal_syscall

    cli

    swapgs

    pop %rax
    mov %ax, %ds
    mov %ax, %es

    popaq

    add $REGISTERS_UNUSED_OFF, %rsp
    iretq

.cfi_endproc

.section .text

.extern acpi_enter_sleep_state
.global __enter_sleep_state
__enter_sleep_state:
#ifndef CONFIG_ACPI
    jne .failure
#else
    # I'm sure this doesn't work, TODO
    # Okay, to do this we'll need to save every register
    # rax doesn't matter since we're using it to return a value anyway
    # Make sure to write everything to memory
    wbinvd
    # Enter the sleep state via assembly
    call acpi_enter_sleep_state
    # In C this would be if(ACPI_FAILURE(st)) goto failure;
    cmp $0, %rax
#endif
    jne .failure
    # Woah, we're back from sleep
    # Restore registers and flush caches
.return:
    wbinvd
    # Flush the TLB
    mov %cr3, %rdi
    mov %rdi, %cr3
    RET
.failure:
    mov $-1, %rax
    jmp .return
