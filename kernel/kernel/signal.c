/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <signal.h>
#include <stdio.h>
#include <errno.h>

#include <kernel/cpu.h>
#include <kernel/vmm.h>
#include <kernel/signal.h>
#include <kernel/panic.h>
#include <kernel/process.h>
void sys_exit(int exitcode);
void kernel_default_signal(struct signal_info *sig)
{
	switch(sig->signum)
	{
		case SIGABRT:
		{
			printk("sig: Aborting!\n");
			break;
		}
		case SIGSEGV:
		{
			printk("Segmentation fault\n");
			get_current_process()->signal_pending = 0;
			sys_exit(127);
			break;
		}
	}
}
#if defined(__x86_64__)
/* TODO: Support signals per thread */
void signal_transfer_to_userspace(struct signal_info *sig, registers_t *regs, _Bool is_int)
{
	/* Start setting the register state for the register switch */
	/* Note that we're saving the old ones */
	uintptr_t *userspace_stack = NULL;
	process_t *process = get_current_process();
	if(!is_int)
	{
		memcpy((registers_t*) &process->old_regs, regs, sizeof(registers_t));
		regs->rdi = sig->signum;
		regs->rip = (uintptr_t) process->sigtable[sig->signum].sa_handler;
		userspace_stack = (uintptr_t *) regs->rsp;
	}
	else
	{
		intctx_t *intctx = (intctx_t*) regs;
		process->old_regs.rax = intctx->rax;
		process->old_regs.rbx = intctx->rbx;
		process->old_regs.rcx = intctx->rcx;
		process->old_regs.rdx = intctx->rdx;
		process->old_regs.rdi = intctx->rdi;
		process->old_regs.rsi = intctx->rsi;
		process->old_regs.rbp = intctx->rbp;
		process->old_regs.rsp = intctx->rsp;
		process->old_regs.rip = intctx->rip;
		process->old_regs.r8 = intctx->r8;
		process->old_regs.r9 = intctx->r9;
		process->old_regs.r10 = intctx->r10;
		process->old_regs.r11 = intctx->r11;
		process->old_regs.r12 = intctx->r12;
		process->old_regs.r13 = intctx->r13;
		process->old_regs.r14 = intctx->r14;
		process->old_regs.r15 = intctx->r15;
		process->old_regs.ds = intctx->ds;
		process->old_regs.ss = intctx->ss;
		process->old_regs.cs = intctx->cs;
		process->old_regs.rflags = intctx->rflags;
		intctx->rdi = sig->signum;
		intctx->rip = (uintptr_t) process->sigtable[sig->signum].sa_handler;
		userspace_stack = (uintptr_t *) intctx->rsp;
	}
	if(userspace_stack && vmm_is_mapped(userspace_stack))
	{
		uintptr_t sigreturn = (uintptr_t) process->sigtable[sig->signum].sa_restorer;
		*userspace_stack = sigreturn;
	}
}
#else
#error "Implement this in your architecture"
#endif
void handle_signal(registers_t *regs, _Bool is_int)
{
	process_t *curr_proc = get_current_process();
	if(!curr_proc)
		panic("Signal invoked without a process!");
	if(curr_proc->signal_dispatched == 1)
		return;

	struct signal_info *sig = &curr_proc->sinfo;

	void (*handler)(int) = curr_proc->sigtable[sig->signum].sa_handler;
	if(handler == (sighandler_t) SIG_IGN) // Ignore the signal if it's handler is set to SIG_IGN
		return;
	if(handler != SIG_DFL)
	{
		if(!vmm_is_mapped(handler))
			return;
		signal_transfer_to_userspace(sig, regs, is_int);
		curr_proc->signal_dispatched = 1;
		return;
	}
	else
	{
		kernel_default_signal(sig);
	}
	curr_proc->signal_pending = 0;
}
int sys_kill(pid_t pid, int sig)
{
	process_t *p = NULL;
	if((int)pid > 0)
	{
		if(pid == get_current_process()->pid)
		{
			p = get_current_process();
		}
		else
			p = get_process_from_pid(pid);
		if(!p)
			return errno =-ESRCH;	
	}
	if(sig == 0)
		return 0;
	if(sig > 26)
		return errno =-EINVAL;
	if(sig < 0)
		return errno =-EINVAL;
	get_current_process()->signal_pending = 1;
	get_current_process()->sinfo.signum = sig;
	return 0;
}
void kernel_raise_signal(int sig, process_t *process)
{
	process->signal_pending = 1;
	process->sinfo.signum = sig;
}
extern void __sigret_return(uintptr_t stack);
void sys_sigreturn(void)
{
	DISABLE_INTERRUPTS();
	/* Switch the registers again */
	registers_t *regs = (registers_t *) get_current_thread()->kernel_stack;
	registers_t *old = (registers_t*) &get_current_process()->old_regs;
	regs->rax = old->rax;
	regs->rbx = old->rbx;
	regs->rcx = old->rcx;
	regs->rdx = old->rdx;
	regs->rdi = old->rdi;
	regs->rsi = old->rsi;
	regs->rbp = old->rbp;
	regs->rsp = old->rsp;
	regs->rip = old->rip;
	regs->r8 = old->r8;
	regs->r9 = old->r9;
	regs->r10 = old->r10;
	regs->r11 = old->r11;
	regs->r12 = old->r12;
	regs->r13 = old->r13;
	regs->r14 = old->r14;
	regs->r15 = old->r15;
	regs->ds = old->ds;
	regs->ss = old->ss;
	regs->cs = old->cs;
	regs->rflags = old->rflags;
	get_current_process()->signal_pending = 0;
	get_current_process()->signal_dispatched = 0;
	__sigret_return((uintptr_t) get_current_thread()->kernel_stack);
	__builtin_unreachable();
}
int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	if(signum > _NSIG)
		return -EINVAL;
	if(vmm_check_pointer((struct sigaction*) act, sizeof(struct sigaction)) < 0 && act)
		return -EFAULT;
	if(vmm_check_pointer(oldact, sizeof(struct sigaction)) < 0 && oldact)
		return -EFAULT;
	/* If both pointers are NULL, just return 0 (We can't do anything) */
	if(!oldact && !act)
		return 0;
	process_t *proc = get_current_process();

	/* Lock the mutex */
	mutex_lock(&proc->signal_lock);

	/* If old_act, save the old action */
	if(oldact)
	{
		memcpy(oldact, &proc->sigtable[signum], sizeof(struct sigaction));
	}
	/* If act, set the new action */
	if(act)
	{
		if(act->sa_handler == SIG_ERR)
		{
			mutex_unlock(&proc->signal_lock);
			return -EINVAL;
		}
		/* Check if it's actually possible to set a handler to this signal */
		switch(signum)
		{
			/* If not, return EINVAL */
			case SIGKILL:
			case SIGSTOP:
				mutex_unlock(&proc->signal_lock);
				return -EINVAL;
		}
		memcpy(&proc->sigtable[signum], act, sizeof(struct sigaction));
	}
	mutex_unlock(&proc->signal_lock);
	return 0;
}
