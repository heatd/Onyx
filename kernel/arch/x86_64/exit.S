/*
 Copyright (c) 2016, 2017, 2018 Pedro Falcato
 This file is part of Onyx, and is released under the terms of the MIT License
 check LICENSE at the root directory for more information
*/

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
	ret
