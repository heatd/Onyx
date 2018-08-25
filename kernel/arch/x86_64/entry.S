/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/x86/gs-offsets.h>
#include <onyx/x86/syscall.h>

.section .text

# Syscall ABI details:
# Arguments are passed on %rdi, %rsi, %rdx, %r10, %r8 and %r9
# Syscall number passed in %rax
# Return address is stored in %rcx by the syscall instruction
# RFLAGS stored in r11
# Registers %rbx, %rsp, %rbp, %r12-15 are preserved
# Registers %rax, %rcx, %r11 are clobbered

.macro SAVE_PRESERVED_SYSCALL_REGS
	# First get the user stack
	mov %gs:0x18, %r11

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

#define KERNEL_DS		0x10

.global syscall_ENTRY64
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
	mov %rsp, %gs:0x18
	mov %gs:0x10, %rsp

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

	# End the stack frame list
	xor %rbp, %rbp

	sti
	
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

	cli

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

.cfi_endproc

.extern AcpiEnterSleepState
.global __enter_sleep_state
__enter_sleep_state:
	# I'm sure this doesn't work, TODO
	# Okay, to do this we'll need to save every register
	# rax doesn't matter since we're using it to return a value anyway
	# Make sure to write everything to memory
	wbinvd
	# Enter the sleep state via assembly
	call AcpiEnterSleepState
	# In C this would be if(ACPI_FAILURE(st)) goto failure;
	cmp $0, %rax
	jne .failure
	# Woah, we're back from sleep
	# Restore registers and flush caches
.return:
	wbinvd
	# Flush the TLB
	mov %cr3, %rdi
	mov %rdi, %cr3
	ret
.failure:
	mov $-1, %rax
	jmp .return
