/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/registers.h>
#include <onyx/x86/segments.h>
#include <onyx/x86/asm.h>

#define REGISTERS_UNUSED_OFF		16

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

.macro INTERRUPT_STACK_ALIGN
	/* After pushing the interrupt frame we're left with an 8-byte aligned stack,
	 * so align it by subbing 8 bytes
	*/
	sub $8, %rsp
.endm

.macro INTERRUPT_STACK_RESTORE
	add $8, %rsp
.endm

.section .text
.global return_from_execve

# Entry point is at RDI, stack at RSI
return_from_execve:
	# Wipe unused registers to avoid leaks
	xor %rbx, %rbx
	xor %rbp, %rbp
	xor %r10, %r10
	xor %r12, %r12
	xor %r13, %r13
	xor %r14, %r14
	xor %r15, %r15
	
	# rdi and rsi aren't zero'd here, only in a few instructions ahead since
	# they hold RIP and RSP
	xor %rdx, %rdx
	xor %rcx, %rcx
	xor %r8, %r8
	xor %r9, %r9

	cli
	swapgs

	mov $0x33, %ax
	mov %ax, %ds
	mov %ax, %es

	push $0x33
	push %rsi
	push $0x202
	push $0x2b
	push %rdi

	iretq

.global __cxa_atexit
__cxa_atexit:
	# NOTE: We can do this with __cxa_atexit because we, as the kernel, will never exit!
	xor %eax, %eax
	RET

/* extern "C" 
[[noreturn]]
void x86_context_switch(thread *prev **%rdi** , unsigned char *stack **%rsi**, bool needs_to_kill_prev **%dx**);
*/
.global x86_context_switch
.type x86_context_switch, @function
x86_context_switch:
	cli
	/* First thing to do: switch the %rsp */
	/* Then we can try to put the thread */
	mov %rsi, %rsp
	INTERRUPT_STACK_ALIGN
	cmp $1, %dx
	je 2f
1:
	jmp x86_interrupt_ret

2:
	/* note that prev is already in %rdi, no need to move it in */
	/* We also don't need to preserve any registers */
	call x86_thread_put
	jmp 1b
