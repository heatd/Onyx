/*
 * Copyright (c) 2019 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#include <onyx/cpu.h>
#include <onyx/vm.h>
#include <onyx/signal.h>
#include <onyx/panic.h>
#include <onyx/process.h>

#include <onyx/x86/segments.h>
#include <onyx/x86/signal.h>
#include <onyx/x86/eflags.h>

/* The sysv abi defines a 128 byte zone below the stack so we need to be
 * careful as to not touch it
*/
#define REDZONE_OFFSET		128
#include <onyx/fpu.h>

int signal_setup_context(struct sigpending *pend, struct k_sigaction *k_sigaction, struct registers *regs)
{
	int sig = pend->signum;
	struct thread *curr = get_current_thread();
	struct signal_info *sinfo = &curr->sinfo;
	unsigned long sp = regs->rsp - REDZONE_OFFSET;

	/* Note that we handle the redzone preservation up here, because when running on an altstack 
	 * we don't need to do that.
	 */
	if(k_sigaction->sa_flags & SA_ONSTACK && !(sinfo->altstack.ss_flags & SS_DISABLE))
	{
		sp = (unsigned long) sinfo->altstack.ss_sp + sinfo->altstack.ss_size;
		if(sinfo->altstack.ss_flags & SS_AUTODISARM)
		{
			sinfo->altstack.ss_sp = NULL;
			sinfo->altstack.ss_size = 0;
			sinfo->altstack.ss_flags = SS_DISABLE;
		}
	}

	size_t fpu_size = fpu_get_save_size();
	/* Start setting the register state for the register switch */
	/* Note that we're saving the old ones */

	/* We need a 16 byte aligned location here, as the stack will point here */
	/* Redzone is already handled */
	unsigned long sframe_location = sp - sizeof(struct sigframe) - fpu_size;
	sframe_location &= -16;

	struct sigframe *sframe = (struct sigframe *) sframe_location;

	if(copy_to_user(&sframe->retaddr, &k_sigaction->sa_restorer, sizeof(void *)) < 0)
		return -EFAULT;

	if(k_sigaction->sa_flags & SA_SIGINFO)
	{
		if(copy_to_user(&sframe->sinfo, pend->info, sizeof(siginfo_t)) < 0)
			return -EFAULT;
	}

	/* Set-up the ucontext */
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RAX], &regs->rax, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RBX], &regs->rbx, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RCX], &regs->rcx, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RDX], &regs->rdx, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RDI], &regs->rdi, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RSI], &regs->rsi, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RBP], &regs->rbp, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RSP], &regs->rsp, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R8], &regs->r8, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R9], &regs->r9, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R10], &regs->r10, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R11], &regs->r11, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R12], &regs->r12, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R13], &regs->r13, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R14], &regs->r14, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R15], &regs->r15, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_CSGSFS], &regs->cs, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_EFL], &regs->rflags, sizeof(unsigned long)) < 0)
		return -EFAULT;
	if(copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RIP], &regs->rip, sizeof(unsigned long)) < 0)
		return -EFAULT;

	/* We're saving the sigmask, that will then be restored */
	if(copy_to_user(&sframe->uc.uc_sigmask, &curr->sinfo.sigmask, sizeof(sigset_t)) < 0)
		return -EFAULT;

	save_fpu(curr->fpu_area);

	if(copy_to_user(&sframe->fpregs, curr->fpu_area, fpu_size) < 0)
		return -EFAULT;
	
	void *fpregs = &sframe->fpregs;

	if(copy_to_user(&sframe->uc.uc_mcontext.fpregs, &fpregs, sizeof(void *)) < 0)
		return -EFAULT;
	
	/* Align the stack to 16 bytes, specified by the ABI */
	regs->rsp = (unsigned long) sframe;
	regs->rip = (unsigned long) k_sigaction->sa_handler;
	regs->rdi = sig;

	if(k_sigaction->sa_flags & SA_SIGINFO)
	{
		regs->rsi = (unsigned long) &sframe->sinfo;
		regs->rdx = (unsigned long) &sframe->uc;
	}

	regs->rflags &= ~(EFLAGS_TRAP | EFLAGS_DIRECTION);

	return 0;
}

extern "C"
__attribute__((noreturn))
void __sigret_return(struct registers *regs);

extern "C"
void sys_sigreturn(struct syscall_frame *sysframe)
{
	/* Switch the registers again */
	struct registers rbuf;
	struct registers *regs = &rbuf;
	struct sigframe *sframe = (struct sigframe *) (sysframe->user_sp - 8);

	/* Set-up the ucontext */
	if(copy_from_user(&regs->rax, &sframe->uc.uc_mcontext.gregs[REG_RAX], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rbx, &sframe->uc.uc_mcontext.gregs[REG_RBX], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rcx, &sframe->uc.uc_mcontext.gregs[REG_RCX], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rdx, &sframe->uc.uc_mcontext.gregs[REG_RDX], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rdi, &sframe->uc.uc_mcontext.gregs[REG_RDI], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rsi, &sframe->uc.uc_mcontext.gregs[REG_RSI], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rbp, &sframe->uc.uc_mcontext.gregs[REG_RBP], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rsp, &sframe->uc.uc_mcontext.gregs[REG_RSP], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->r8, &sframe->uc.uc_mcontext.gregs[REG_R8], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->r9, &sframe->uc.uc_mcontext.gregs[REG_R9], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->r10, &sframe->uc.uc_mcontext.gregs[REG_R10], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->r11, &sframe->uc.uc_mcontext.gregs[REG_R11], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->r12, &sframe->uc.uc_mcontext.gregs[REG_R12], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->r13, &sframe->uc.uc_mcontext.gregs[REG_R13], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->r14, &sframe->uc.uc_mcontext.gregs[REG_R14], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->r15, &sframe->uc.uc_mcontext.gregs[REG_R15], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rflags, &sframe->uc.uc_mcontext.gregs[REG_EFL], sizeof(unsigned long)) < 0)
		return;
	if(copy_from_user(&regs->rip, &sframe->uc.uc_mcontext.gregs[REG_RIP], sizeof(unsigned long)) < 0)
		return;

	/* Force ss, ds and cs so there isn't a privilege exploit */
	regs->ss = regs->ds = USER_DS;
	regs->cs = USER_CS;
	/* Also, force interrupts, as we're returning to userspace  */
	regs->rflags |= EFLAGS_INT_ENABLED;
	
	struct thread *curr = get_current_thread();
	void *fpregs;

	if(copy_from_user(&fpregs, &sframe->uc.uc_mcontext.fpregs, sizeof(void *)) < 0)
		return;
	
	/* We need to disable interrupts here to avoid corruption of the fpu state */
	DISABLE_INTERRUPTS();
	if(copy_from_user(curr->fpu_area, fpregs, fpu_get_save_size()) < 0)
		return;

	restore_fpu(curr->fpu_area);

	ENABLE_INTERRUPTS();

	/* Restore the old sigmask */
	sigset_t set;
	if(copy_from_user(&set, &sframe->uc.uc_sigmask, sizeof(set)) < 0)
		return;
	
	curr->sinfo.set_blocked(&set);

	context_tracking_exit_kernel();
	__sigret_return(regs);

	__builtin_unreachable();
}

extern "C"
void do_signal_syscall(uint64_t syscall_ret, struct syscall_frame *syscall_ctx, struct registers *regs)
{
	regs->cs = USER_CS;
	regs->ds = regs->ss = syscall_ctx->ds;
	regs->r8 = syscall_ctx->r8;
	regs->r9 = syscall_ctx->r9;
	regs->r10 = syscall_ctx->r10;
	regs->r11 = 0;
	regs->r12 = syscall_ctx->r12;
	regs->r13 = syscall_ctx->r13;
	regs->r14 = syscall_ctx->r14;
	regs->r15 = syscall_ctx->r15;
	regs->rax = syscall_ret;
	regs->rbx = syscall_ctx->rbx;
	regs->rcx = 0;
	regs->rip = syscall_ctx->rip;
	regs->rflags = syscall_ctx->rflags;
	regs->rbp = syscall_ctx->rbp;
	regs->rdx = syscall_ctx->rdx;
	regs->rdi = syscall_ctx->rdi;
	regs->rsi = syscall_ctx->rsi;
	regs->rsp = syscall_ctx->user_sp;

	handle_signal(regs);
}
