/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <errno.h>

#include <kernel/cpu.h>
#include <kernel/vmm.h>
#include <kernel/signal.h>
#include <kernel/panic.h>
#include <kernel/process.h>

void signal_default_term(int signum)
{
	process_exit_from_signal(signum);
}
void signal_default_core(int signum)
{
	/* TODO: Generate a core dump */
	signal_default_term(signum);
}
void signal_default_ignore(int signum)
{
	(void) signum;
}
void signal_default_cont(int signum)
{
	(void) signum;
	/* TODO: Handle */
}
void signal_default_stop(int signum)
{
	(void) signum;
	/* TODO: Handle */
}
sighandler_t dfl_signal_handlers[] = {
	[SIGHUP] = signal_default_term,
	[SIGINT] = signal_default_term,
	[SIGQUIT] = signal_default_core,
	[SIGILL] = signal_default_core,
	[SIGABRT] = signal_default_core,
	[SIGFPE] = signal_default_core,
	[SIGKILL] = signal_default_term,
	[SIGSEGV] = signal_default_core,
	[SIGPIPE] = signal_default_term,
	[SIGALRM] = signal_default_term,
	[SIGTERM] = signal_default_term,
	[SIGUSR1] = signal_default_term,
	[SIGUSR2] = signal_default_term,
	[SIGCHLD] = signal_default_ignore,
	[SIGCONT] = signal_default_cont,
	[SIGSTOP] = signal_default_stop,
	[SIGTSTP] = signal_default_stop,
	[SIGTTIN] = signal_default_stop,
	[SIGTTOU] = signal_default_stop
};
void signal_update_pending(process_t *process);
#define SST_SIZE (_NSIG/8/sizeof(long))
void signotset(sigset_t *set)
{
	for(size_t i = 0; i < SST_SIZE; i++)
		set->__bits[i] = ~set->__bits[i];
}
void sys_exit(int exitcode);
void kernel_default_signal(int signum)
{
	signal_update_pending(get_current_process());
	dfl_signal_handlers[signum](signum);
}
#if defined(__x86_64__)
/* TODO: Support signals per thread */
void signal_transfer_to_userspace(int sig, registers_t *regs, _Bool is_int)
{
	/* Start setting the register state for the register switch */
	/* Note that we're saving the old ones */
	uintptr_t *userspace_stack = NULL;
	process_t *process = get_current_process();
	if(!is_int)
	{
		memcpy((registers_t*) &process->old_regs, regs, sizeof(registers_t));
		regs->rdi = sig;
		regs->rip = (uintptr_t) process->sigtable[sig].sa_handler;
		regs->cs = 0x2b;
		regs->ds = regs->ss = 0x33;
		if(process->old_regs.ds == 0x33)
			userspace_stack = (uintptr_t *) regs->rsp;
		else
		{
			userspace_stack = get_current_thread()->user_stack;
			regs->rsp = (uintptr_t) userspace_stack;
		}
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
		intctx->rdi = sig;
		intctx->rip = (uintptr_t) process->sigtable[sig].sa_handler;
		intctx->cs = 0x33;
		intctx->ds = intctx->ss = 0x2b;
		if(process->old_regs.ds == 0x2b)
			userspace_stack = (uintptr_t *) intctx->rsp;
		else
		{
			userspace_stack = get_current_thread()->user_stack;
			intctx->rsp = (uintptr_t) userspace_stack;
		}
	}
	if(userspace_stack && vmm_is_mapped(userspace_stack))
	{
		uintptr_t sigreturn = (uintptr_t) process->sigtable[sig].sa_restorer;
		*userspace_stack = sigreturn;
	}
}
#else
#error "Implement this in your architecture"
#endif
int signal_find(process_t *process)
{
	sigset_t *set = &process->pending_set;
	sigset_t *blocked_set = &process->sigmask;
	for(int i = 0; i < NSIG; i++)
	{
		if(sigismember(set, i) && !sigismember(blocked_set, i))
		{
			sigdelset(set, i);
			return i;
		}
	}
	return 0;
}
_Bool signal_is_empty(process_t *process)
{
	sigset_t *set = &process->pending_set;
	sigset_t *blocked_set = &process->sigmask;
	for(int i = 0; i < NSIG; i++)
	{
		if(sigismember(set, i) && !sigismember(blocked_set, i))
			return true;
	}
	return false;
}
void handle_signal(registers_t *regs, _Bool is_int)
{
	/* We can't do signals while in kernel space */
	if(regs->cs == 0x8)
	{
		return;
	}
	process_t *current = get_current_process();
	//assert(current);

	/* Find an available signal */
	int signum = signal_find(current);
	struct sigaction *sigaction = &current->sigtable[signum];
	void (*handler)(int) = sigaction->sa_handler;
	bool is_siginfo = (bool) sigaction->sa_flags & SA_SIGINFO;
	UNUSED(is_siginfo);
	/* TODO: Handle SA_SIGINFO */
	/* TODO: Handle SA_RESTART */
	/* TODO: Handle SA_NODEFER */
	/* TODO: Handle SA_NOCLDWAIT */
	/* TODO: Handle SA_ONSTACK */
	/* TODO: Handle SA_NOCLDSTOP */
	if(sigaction->sa_flags & SA_RESETHAND)
	{
		/* If so, we need to reset the handler to SIG_DFL and clear SA_SIGINFO */
		sigaction->sa_handler = SIG_DFL;
		sigaction->sa_flags &= ~SA_SIGINFO;
	}
	if(handler != SIG_DFL)
	{
		if(!vmm_is_mapped(handler))
			return;
		signal_transfer_to_userspace(signum, regs, is_int);
		return;
	}
	else
	{
		kernel_default_signal(signum);
	}
	if(signal_is_empty(current))
		current->signal_pending = 0;
}
void signal_update_pending(process_t *process)
{
	sigset_t *set = &process->pending_set;
	sigset_t *blocked_set = &process->sigmask;
	for(int i = 0; i < NSIG; i++)
	{
		if(sigismember(set, i) && !sigismember(blocked_set, i))
		{
			process->signal_pending = 1;
			return;
		}
	}
	process->signal_pending = 0;
}
void kernel_raise_signal(int sig, process_t *process)
{
	/* Don't bother to set it as pending if sig == SIG_IGN */
	if(process->sigtable[sig].sa_handler == SIG_IGN)
		return;
	sigaddset(&process->pending_set, sig);
	if(!sigismember(&process->sigmask, sig))
		process->signal_pending = 1;
}
_Bool signal_is_masked(process_t *process, int sig)
{
	sigset_t *set = &process->sigmask;
	return (_Bool) sigismember(set, sig);
}
int sys_kill(pid_t pid, int sig)
{
	process_t *p = NULL;
	process_t *current = get_current_process();
	if((int)pid > 0)
	{
		if(pid == current->pid)
		{
			p = current;
		}
		else
			p = get_process_from_pid(pid);
		if(!p)
			return errno =-ESRCH;	
	}
	if(sig == 0)
		return 0;
	if(sig > NSIG)
		return errno =-EINVAL;
	if(sig < 0)
		return errno =-EINVAL;
	kernel_raise_signal(sig, p);
	return 0;
}
extern void __sigret_return(uintptr_t stack);
void sys_sigreturn(void)
{
	DISABLE_INTERRUPTS();
	signal_update_pending(get_current_process());
	/* Switch the registers again */
	uintptr_t *regs = (uintptr_t *) get_current_thread()->kernel_stack;
	registers_t *old = (registers_t*) &get_current_process()->old_regs;
	*--regs = old->ds; //SS
	*--regs = old->rsp; //RSP
	*--regs = old->rflags; // RFLAGS
	*--regs = old->cs; //CS
	*--regs = old->rip; //RIP
	*--regs = old->rax; // RAX
	*--regs = old->rbx; // RBX
	*--regs = old->rcx; // RCX
	*--regs = old->rdx; // RDX
	*--regs = old->rdi; // RDI
	*--regs = old->rsi; // RSI
	*--regs = old->rbp; // RBP
	*--regs = old->r15; // R15
	*--regs = old->r14; // R14
	*--regs = old->r13; // R13
	*--regs = old->r12; // R12
	*--regs = old->r11; // R11
	*--regs = old->r10; // R10
	*--regs = old->r9; // R9
	*--regs = old->r8; // R8
	*--regs = old->ds; // DS
	__sigret_return((uintptr_t) regs);
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
int sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	process_t *current = get_current_process();
	if(oldset)
	{
		if(vmm_check_pointer(oldset, sizeof(sigset_t)) < 0)
			return -EFAULT;
		memcpy(oldset, &current->sigmask, sizeof(sigset_t));
	}
	if(set)
	{
		if(vmm_check_pointer((void*) set, sizeof(sigset_t)) < 0)
			return -EFAULT;
		
		switch(how)
		{
			case SIG_BLOCK:
			{
				sigorset(&current->sigmask, &current->sigmask, set);
				if(sigismember(&current->sigmask, SIGKILL))
					sigdelset(&current->sigmask, SIGKILL);
				if(sigismember(&current->sigmask, SIGSTOP))
					sigdelset(&current->sigmask, SIGSTOP);
				break;
			}
			case SIG_UNBLOCK:
			{
				sigset_t s;
				memcpy(&s, set, sizeof(sigset_t));
				signotset(&s);
				sigandset(&current->sigmask, &current->sigmask, &s); 
				break;
			}
			case SIG_SETMASK:
			{
				memcpy(&current->sigmask, set, sizeof(sigset_t));
				break;
			}
			default:
				return -EINVAL;
		}
	}
	signal_update_pending(current);
	return 0;
}
bool signal_is_pending(void)
{
	return (bool) get_current_process()->signal_pending;
}
int sys_sigsuspend(const sigset_t *set)
{
	if(vmm_check_pointer((void*) set, sizeof(sigset_t)) < 0)
		return -EFAULT;
	process_t *current = get_current_process();
	
	/* Ok, mask the signals in set */
	sigset_t old;
	/* First, save the old sigset */
	memcpy(&old, &current->sigmask, sizeof(sigset_t));
	/* Now, set the signal mask */
	memcpy(&current->sigmask, set, sizeof(sigset_t));

	/* Now, wait for a signal */
	while(!signal_is_pending())
		sched_yield();
	memcpy(&current->sigmask, &old, sizeof(sigset_t));
	return -EINTR;
}
int sys_pause(void)
{
	while(!signal_is_pending())
		sched_yield();
	return -EINTR;
}
