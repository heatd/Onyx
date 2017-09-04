/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#include <kernel/process.h>
#include <kernel/paging.h>
#include <kernel/ptrace.h>
#include <kernel/vmm.h>
#include <kernel/fpu.h>

#include <sys/ptrace.h>

int ptrace_peek(struct process *process, void *addr, ptrace_word_t *word)
{
	int status = 0;
	/* Save the old VMM tree */
	//avl_node_t *old_tree = vmm_get_tree();

	/* Set the vmm tree before changing CR3, as changing cr3 is very expensive(saves performance on invalid requests) */
	//vmm_set_tree(process->tree);
	
	/* Lock the address space */
	acquire_spinlock(&process->vm_spl);
	/* Load the actual address space */
	paging_load_cr3(process->cr3);

	/* Do the actual copy */
	if(copy_from_user(word, addr, sizeof(ptrace_word_t)) < 0)
	{
		status = -1;
		errno = EFAULT;
	}

	/* Unlock the address space */
	release_spinlock(&process->vm_spl);
	
	/* Restore the old context */
	//vmm_set_tree(old_tree);
	paging_load_cr3(get_current_process()->cr3);

	return status;
}
int ptrace_poke(struct process *process, void *addr, ptrace_word_t word)
{
	int status = 0;
	/* Save the old VMM tree */
	//avl_node_t *old_tree = vmm_get_tree();

	/* Set the vmm tree before changing CR3, as changing cr3 is very expensive(saves performance on invalid requests) */
	//vmm_set_tree(process->tree);
	
	/* Lock the address space */
	acquire_spinlock(&process->vm_spl);
	/* Load the actual address space */
	paging_load_cr3(process->cr3);

	/* Do the actual copy */
	if(copy_to_user(addr, &word, sizeof(ptrace_word_t)) < 0)
	{
		status = -1;
		errno = EFAULT;
	}

	/* Unlock the address space */
	release_spinlock(&process->vm_spl);
	
	/* Restore the old context */
	//vmm_set_tree(old_tree);
	paging_load_cr3(get_current_process()->cr3);

	return status;
}
int ptrace_getregs(struct process *process, struct user_regs_struct *regs)
{
	/* TODO: We currently don't support multi-threaded ptracing, since in Onyx processes have threads
	 * (instead of linux's threads each have a process hack) */
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
}
int ptrace_getfpregs(struct process *process, struct user_fpregs_struct *regs)
{
	fpu_ptrace_getfpregs((void*) process->threads[0]->fpu_area, regs);
	return 0;
}
