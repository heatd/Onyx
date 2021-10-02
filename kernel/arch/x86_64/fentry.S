/*
 * Copyright (c) 2020 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/x86/segments.h>
#include <onyx/registers.h>

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

.global __fentry__
__fentry__:
	push %rbp
	mov %rsp, %rbp

	/* Setup a struct registers on the stack */
	push $KERNEL_DS /* %ss */
	push %rsp	/* %rsp */
	addq $24, (%rsp) /* adjust regs->rsp to point to the stack before the call */
	pushf		/* rflags */
	push $KERNEL_CS /* %cs */
	push 8(%rbp)	/* %rip */
	push $0		/* int_err_code */
	push $0		/* int_no */
	pushaq		/* all GPRs */
	push $KERNEL_DS	/* %ds */

	mov %rsp, %rdi
	call x86_ktrace_entry

	add $8, %rsp

	popaq
	
	add $(7*8), %rsp

	pop %rbp

	ret

.global __return__
__return__:
	ud2
