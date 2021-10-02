/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#include <onyx/process.h>
#include <onyx/paging.h>
#include <onyx/ptrace.h>
#include <onyx/vm.h>
#include <onyx/fpu.h>
#include <onyx/panic.h>

#include <sys/ptrace.h>

int ptrace_peek(struct process *process, void *addr, ptrace_word_t *word)
{
	return errno = EFAULT, -1;
}

int ptrace_poke(struct process *process, void *addr, ptrace_word_t word)
{
	return errno = EFAULT, -1;
}

int ptrace_getregs(struct process *process, struct user_regs_struct *regs)
{
	/* TODO: We currently don't support multi-threaded ptracing, since in Onyx processes have threads
	 * (instead of linux's threads each have a process hack) */
	return errno = EFAULT, -1;
#if 0
	thread_t *main_thread = process->threads[0];

	/* Registers are stored on the kernel stack(x86_64) */
	registers_t *r = (registers_t *) main_thread->kernel_stack;

	/* Save the registers */
	regs->rax = r->rax;
	regs->rbx = r->rbx;
	regs->rcx = r->rcx;
	regs->rdx = r->rdx;
	regs->rdi = r->rdi;
	regs->rsi = r->rsi;
	regs->rbp = r->rbp;
	regs->rip = r->rip;
	regs->r8 = r->r8;
	regs->r9 = r->r9;
	regs->r10 = r->r10;
	regs->r11 = r->r11;
	regs->r12 = r->r12;
	regs->r13 = r->r13;
	regs->r14 = r->r14;
	regs->r15 = r->r15;
	regs->cs = r->cs;
	regs->eflags = r->rflags;
	regs->rsp = r->rsp;
	regs->ds = regs->ss = regs->es = regs->fs = regs->gs = r->ss;
	regs->fs_base = (uintptr_t) main_thread->fs;
	return 0;
#endif
}
int ptrace_getfpregs(struct process *process, struct user_fpregs_struct *regs)
{
	panic("implement");
	//fpu_ptrace_getfpregs((void*) process->threads[0]->fpu_area, regs);
	return 0;
}
