/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <signal.h>
#include <stdio.h>
#include <errno.h>

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
void signal_transfer_to_userspace(struct signal_info *sig, registers_t *regs, _Bool is_int)
{
	/* Start setting the register state for the register switch */
	/* Note that we're saving the old ones */
	uintptr_t *userspace_stack = NULL;
	if(!is_int)
	{
		memcpy((registers_t*) &get_current_process()->old_regs, regs, sizeof(registers_t));
		regs->rdi = sig->signum;
		regs->rip = (uintptr_t) sig->handler;
		userspace_stack = (uintptr_t *) regs->rsp;
	}
	else
	{
		intctx_t *intctx = (intctx_t*) regs;
		get_current_process()->old_regs.rax = intctx->rax;
		get_current_process()->old_regs.rbx = intctx->rbx;
		get_current_process()->old_regs.rcx = intctx->rcx;
		get_current_process()->old_regs.rdx = intctx->rdx;
		get_current_process()->old_regs.rdi = intctx->rdi;
		get_current_process()->old_regs.rsi = intctx->rsi;
		get_current_process()->old_regs.rbp = intctx->rbp;
		get_current_process()->old_regs.rsp = intctx->rsp;
		get_current_process()->old_regs.rip = intctx->rip;
		get_current_process()->old_regs.r8 = intctx->r8;
		get_current_process()->old_regs.r9 = intctx->r9;
		get_current_process()->old_regs.r10 = intctx->r10;
		get_current_process()->old_regs.r11 = intctx->r11;
		get_current_process()->old_regs.r12 = intctx->r12;
		get_current_process()->old_regs.r13 = intctx->r13;
		get_current_process()->old_regs.r14 = intctx->r14;
		get_current_process()->old_regs.r15 = intctx->r15;
		get_current_process()->old_regs.ds = intctx->ds;
		get_current_process()->old_regs.ss = intctx->ss;
		get_current_process()->old_regs.cs = intctx->cs;
		get_current_process()->old_regs.rflags = intctx->rflags;
		intctx->rdi = sig->signum;
		intctx->rip = (uintptr_t) sig->handler;
		userspace_stack = (uintptr_t *) intctx->rsp;
	}
	if(userspace_stack && vmm_is_mapped(userspace_stack))
	{
		printf("userspace stack: %p\n", userspace_stack);
		*userspace_stack = (uintptr_t) get_current_process()->sigreturn;
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

	if(sig->handler == (sighandler_t) SIG_IGN) // Ignore the signal if it's handler is set to SIG_IGN
		return;
	if(sig->handler != SIG_DFL)
	{
		if(!vmm_is_mapped(sig->handler))
			return;
		signal_transfer_to_userspace(sig,  regs, is_int);
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
	get_current_process()->sinfo.handler = get_current_process()->sighandlers[sig];
	return 0;
}
sighandler_t sys_signal(int signum, sighandler_t handler)
{
	process_t *proc = get_current_process();
	if(!proc)
		return (sighandler_t) SIG_ERR;
	if(signum > 26)
		return (sighandler_t) SIG_ERR;
	if(signum < 0)
		return (sighandler_t) SIG_ERR;
	if(!vmm_is_mapped(handler))
		return (sighandler_t) SIG_ERR;
	if(handler == (sighandler_t) SIG_IGN)
	{
		/* SIGKILL, SIGSEGV and SIGSTOP can't be masked (yes, I'm also enforcing SIGSEGV to be on(non-standard)*/
		switch(signum)
		{
			case SIGKILL:
			case SIGSEGV:
			case SIGSTOP:
				return (sighandler_t) SIG_ERR;
		}
	}
	sighandler_t ret = proc->sighandlers[signum];
	proc->sighandlers[signum] = handler;

	return ret;
}
extern void __sigret_return(uintptr_t stack);
void sys_sigreturn(void *ret)
{
	if(ret == (void*) -1 && get_current_process()->signal_pending)
	{
		/* Switch the registers again */
		memcpy(get_current_thread()->kernel_stack, (registers_t*) &get_current_process()->old_regs, sizeof(registers_t));
		get_current_process()->signal_pending = 0;
		get_current_process()->signal_dispatched = 0;
		__sigret_return((uintptr_t) get_current_thread()->kernel_stack);
		__builtin_unreachable();
	}
	if(!vmm_is_mapped(ret))
		return;
	get_current_process()->sigreturn = ret;
}