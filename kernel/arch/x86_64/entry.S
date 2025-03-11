/*
 * Copyright (c) 2018 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <platform/syscall.h>
#include <onyx/x86/asm.h>
#include <onyx/x86/segments.h>
#include <onyx/registers.h>

/* Everything here is permanently mapped */
.section .text.x86_entry

.macro pushaq
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rdi
    push %rsi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
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

# Syscall ABI details:
# Arguments are passed on %rdi, %rsi, %rdx, %r10, %r8 and %r9
# Syscall number passed in %rax
# Return address is stored in %rcx by the syscall instruction
# RFLAGS stored in r11
# Registers %rbx, %rsp, %rbp, %r12-15 are preserved
# Registers %rax, %rcx, %r11 are clobbered

.align 64
ENTRY(syscall_ENTRY64)
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

    /* Set up a fake iretq stack frame */
    push $USER_DS
    /* We're filling this with the user rsp when we can */
    push $0
    /* eflags */
    push %r11
    push $USER_CS
    /* %rip */
    push %rcx
    /* push dummy int_err_code and int_no = syscall_nr (%rax) */
    push $-1
    push %rax
    pushaq
    /* %ds */
    mov %ds, %ecx
    push %rcx
    /* Set up the user sp */
    mov %gs:scratch_rsp, %rcx
    mov %rcx, REGISTER_OFF_RSP(%rsp)

    /* Switch to proper kernel data segments */
    mov $KERNEL_DS, %cx
    mov %cx, %ds
    mov %cx, %es

    sti

    /* End the stack frame list */
    xor %rbp, %rbp
    mov %rsp, %rdi

    call do_syscall64
    cmp %al, %al
    jz x86_scheduler_exit

    # Disable the interrupts since we're about to do some naughty stuff with the stack
    cli

    pop %rcx
    mov %cx, %ds
    mov %cx, %es
    popaq
    /* Alright, registers are almost fully restored, except for the user sp, rip and rflags.
     * Snatch them from the iretq stack frame. Note that the previous popaq would've restored
     * rip and rflags, if not for code toggling ->rflags, rip in struct register. */
    mov 16(%rsp), %rcx
    mov 32(%rsp), %r11
    mov 40(%rsp), %rsp
    swapgs
    sysretq
END(syscall_ENTRY64)

.cfi_endproc

.section .text

.extern acpi_enter_sleep_state
ENTRY(__enter_sleep_state)
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
END(__enter_sleep_state)
