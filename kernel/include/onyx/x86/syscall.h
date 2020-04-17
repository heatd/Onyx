/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_SYSCALL_H
#define _ONYX_X86_SYSCALL_H

#include <sys/syscall.h>

#define NR_SYSCALL_MAX		118

#ifndef __ASSEMBLER__
struct syscall_frame
{
	unsigned long ds;

	/* Preserved regs */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long user_rsp;
	
	/* rax holds the syscall nr */
	/* %rdi, %rsi, %rdx, %r10, %r8 and %r9 are args */
	unsigned long r9;
	unsigned long r8;
	unsigned long r10;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long rax;
	
	unsigned long rflags;

	unsigned long rip;
};

#endif

#define SYSCALL_FRAME_CLOBBERED_SIZE 	7 * 8

#define SYSCALL_FRAME_SIZE		18 * 8

#endif
