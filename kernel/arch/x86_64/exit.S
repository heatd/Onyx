/*
 Copyright (c) 2016, 2017 Pedro Falcato
 This file is part of Onyx, and is released under the terms of the MIT License
 check LICENSE at the root directory for more information
*/

.section .text
.global return_from_execve

# Entry point is at RDI, argc at RSI, argv at RDX, envp at RCX, auxv at R8, stack at R9
return_from_execve:
	# Load the registers
	push %rdi
	mov $0x202, %r11
	mov %rsi, %rdi
	mov %rdx, %rsi
	mov %rcx, %rdx
	mov %r8, %rcx
	pop %r8
	# Reload unused registers to avoid leaks
	xor %rbx, %rbx
	xor %rbp, %rbp
	xor %r10, %r10
	xor %r12, %r12
	xor %r13, %r13
	xor %r14, %r14
	xor %r15, %r15
	
	cli
	swapgs

	mov $0x33, %ax
	mov %ax, %ds
	mov %ax, %es

	push $0x33
	push %r9
	xor %r9, %r9
	push $0x202
	push $0x2b
	push %r8

	xor %rax, %rax
	xor %r8, %r8
	iretq
