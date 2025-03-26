/*
 * Copyright (c) 2019 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/registers.h>
#include <onyx/signal.h>
#include <onyx/user.h>
#include <onyx/vm.h>
#include <onyx/x86/eflags.h>
#include <onyx/x86/segments.h>
#include <onyx/x86/signal.h>

#include <uapi/signal.h>

/* The sysv abi defines a 128 byte zone below the stack so we need to be
 * careful as to not touch it
 */
#define REDZONE_OFFSET 128
#include <onyx/fpu.h>

#define get_segment_reg(reg)                                                            \
    ({                                                                                  \
        unsigned long seg;                                                              \
        __asm__ __volatile__("mov %%" reg ", %%rax; mov %%rax, %0" : "=r"(seg)::"rax"); \
        seg;                                                                            \
    })

static bool in_syscall(struct registers *regs)
{
    return regs->int_err_code == -1UL;
}

static int signal_setup_context(int sig, siginfo_t *info, struct k_sigaction *k_sigaction,
                                struct registers *regs)
{
    struct thread *curr = get_current_thread();
    unsigned long sp = regs->rsp - REDZONE_OFFSET;
    stack_t *altstack = &current->altstack;
    /* Note that we handle the redzone preservation up here, because when running on an altstack
     * we don't need to do that.
     */
    if (k_sigaction->sa_flags & SA_ONSTACK)
    {
        if (!(altstack->ss_flags & SS_DISABLE) &&
            !executing_in_altstack((struct syscall_frame *) regs, altstack))
        {
            sp = (unsigned long) altstack->ss_sp + altstack->ss_size;
            if (altstack->ss_flags & SS_AUTODISARM)
                sigaltstack_init(altstack);
        }
    }

    size_t fpu_size = fpu_get_save_size();
    /* Start setting the register state for the register switch */
    /* Note that we're saving the old ones */

    /* We need a 16 byte aligned location here, as the stack will point here */
    /* Redzone is already handled */
    unsigned long sframe_location = sp - sizeof(struct sigframe) - fpu_size;
    sframe_location &= -16;
    sframe_location -= 8;

    struct sigframe *sframe = (struct sigframe *) sframe_location;

    if (copy_to_user(&sframe->retaddr, &k_sigaction->sa_restorer, sizeof(void *)) < 0)
        return -EFAULT;

    if (k_sigaction->sa_flags & SA_SIGINFO)
    {
        if (copy_to_user(&sframe->sinfo, info, sizeof(siginfo_t)) < 0)
            return -EFAULT;
    }

    /* Set-up the ucontext */
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RAX], &regs->rax, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RBX], &regs->rbx, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RCX], &regs->rcx, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RDX], &regs->rdx, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RDI], &regs->rdi, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RSI], &regs->rsi, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RBP], &regs->rbp, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RSP], &regs->rsp, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R8], &regs->r8, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R9], &regs->r9, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R10], &regs->r10, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R11], &regs->r11, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R12], &regs->r12, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R13], &regs->r13, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R14], &regs->r14, sizeof(unsigned long)) < 0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_R15], &regs->r15, sizeof(unsigned long)) < 0)
        return -EFAULT;

    const unsigned long csgsfsss =
        (regs->ss << 48 | get_segment_reg("fs") << 32 | get_segment_reg("gs") << 16 | regs->cs);
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_CSGSFS], &csgsfsss, sizeof(unsigned long)) <
        0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_EFL], &regs->rflags, sizeof(unsigned long)) <
        0)
        return -EFAULT;
    if (copy_to_user(&sframe->uc.uc_mcontext.gregs[REG_RIP], &regs->rip, sizeof(unsigned long)) < 0)
        return -EFAULT;

    /* We're saving the sigmask, that will then be restored */
    sigset_t *mask =
        test_task_flag(current, TF_RESTORE_SIGMASK) ? &current->original_sigset : &current->sigmask;
    clear_task_flag(current, TF_RESTORE_SIGMASK);
    if (copy_to_user(&sframe->uc.uc_sigmask, mask, sizeof(sigset_t)) < 0)
        return -EFAULT;

    save_fpu(curr->fpu_area);

    if (copy_to_user(&sframe->fpregs, curr->fpu_area, fpu_size) < 0)
        return -EFAULT;

    void *fpregs = &sframe->fpregs;

    if (copy_to_user(&sframe->uc.uc_mcontext.fpregs, &fpregs, sizeof(void *)) < 0)
        return -EFAULT;

    // It should be 8 bytes misaligned
    assert((sframe_location & 0xf) == 0x8);

    /* Align the stack to 16 bytes, specified by the ABI */
    regs->rsp = sframe_location;
    regs->rip = (unsigned long) k_sigaction->sa_handler;
    regs->rdi = sig;

    if (k_sigaction->sa_flags & SA_SIGINFO)
    {
        regs->rsi = (unsigned long) &sframe->sinfo;
        regs->rdx = (unsigned long) &sframe->uc;
    }

    regs->rflags &= ~(EFLAGS_TRAP | EFLAGS_DIRECTION);

    return 0;
}

static int fault_in_range(u8 *start, size_t len)
{
    u8 *end = page_align_up(start + len);
    unsigned long addr = (unsigned long) start;
    u8 *ptr;
    unsigned int dummy;
    int err = 0;

    /* Page align our buffer */
    if (addr & (PAGE_SIZE - 1))
    {
        err = get_user32((unsigned int *) (addr & -4), &dummy);
        if (err < 0)
            return err;
        start = page_align_up(start);
    }

    for (ptr = start; ptr < end; ptr += PAGE_SIZE)
    {
        err = get_user32((unsigned int *) ptr, &dummy);
        if (err < 0)
            return err;
    }

    return err;
}

static int restore_fpu_sigframe(void *fpregs)
{
    struct thread *curr = get_current_thread();
    size_t fpu_size = fpu_get_save_size();
    int err;

    /* We need to disable interrupts (and faulting) here to avoid corruption of the fpu state */
    for (;;)
    {
        irq_disable();
        pagefault_disable();
        if (copy_from_user(curr->fpu_area, fpregs, fpu_size) < 0)
        {
            /* Copying failed. Enable faulting again and try to copy it in. It's okay that fpu_area
             * has bad FPU state, we'll never load from it anyway. */
            pagefault_enable();
            irq_enable();
            err = fault_in_range(fpregs, fpu_size);
            if (err < 0)
                return err;
        }
        else
            break;
    }

    restore_fpu(curr->fpu_area);
    pagefault_enable();
    irq_enable();
    return 0;
}

unsigned long sys_sigreturn(struct syscall_frame *sysframe)
{
    /* Switch the registers again */
    struct registers *regs = (struct registers *) sysframe;
    struct sigframe *sframe = (struct sigframe *) (sysframe->rsp - 8);
    void *fpregs;

    /* Set-up the ucontext */
    if (copy_from_user(&regs->rax, &sframe->uc.uc_mcontext.gregs[REG_RAX], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->rbx, &sframe->uc.uc_mcontext.gregs[REG_RBX], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->rcx, &sframe->uc.uc_mcontext.gregs[REG_RCX], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->rdx, &sframe->uc.uc_mcontext.gregs[REG_RDX], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->rdi, &sframe->uc.uc_mcontext.gregs[REG_RDI], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->rsi, &sframe->uc.uc_mcontext.gregs[REG_RSI], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->rbp, &sframe->uc.uc_mcontext.gregs[REG_RBP], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->rsp, &sframe->uc.uc_mcontext.gregs[REG_RSP], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->r8, &sframe->uc.uc_mcontext.gregs[REG_R8], sizeof(unsigned long)) < 0)
        goto fault;
    if (copy_from_user(&regs->r9, &sframe->uc.uc_mcontext.gregs[REG_R9], sizeof(unsigned long)) < 0)
        goto fault;
    if (copy_from_user(&regs->r10, &sframe->uc.uc_mcontext.gregs[REG_R10], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->r11, &sframe->uc.uc_mcontext.gregs[REG_R11], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->r12, &sframe->uc.uc_mcontext.gregs[REG_R12], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->r13, &sframe->uc.uc_mcontext.gregs[REG_R13], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->r14, &sframe->uc.uc_mcontext.gregs[REG_R14], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->r15, &sframe->uc.uc_mcontext.gregs[REG_R15], sizeof(unsigned long)) <
        0)
        goto fault;
    if (copy_from_user(&regs->rflags, &sframe->uc.uc_mcontext.gregs[REG_EFL],
                       sizeof(unsigned long)) < 0)
        goto fault;
    if (copy_from_user(&regs->rip, &sframe->uc.uc_mcontext.gregs[REG_RIP], sizeof(unsigned long)) <
        0)
        goto fault;

    /* Force ss, ds and cs so there isn't a privilege exploit */
    regs->ss = regs->ds = USER_DS;
    regs->cs = USER_CS;
    /* We are _not_ inside a system call */
    regs->int_err_code = -1UL;
    /* Also, force interrupts, as we're returning to userspace  */
    regs->rflags |= EFLAGS_INT_ENABLED;

    if (copy_from_user(&fpregs, &sframe->uc.uc_mcontext.fpregs, sizeof(void *)) < 0)
        goto fault;

    if (restore_fpu_sigframe(fpregs))
        goto fault;
    /* Restore the old sigmask */
    sigset_t set;
    if (copy_from_user(&set, &sframe->uc.uc_sigmask, sizeof(set)) < 0)
        goto fault;

    signal_setmask(&set);
    return regs->rax;
fault:
    force_sigsegv(0);
    return 0;
}

static void deliver_signal(struct arch_siginfo *sinfo, struct registers *regs)
{
    struct k_sigaction *ksa = &sinfo->action;
    if (in_syscall(regs))
    {
        /* Only restart ERESTARTSYS (if SA_RESTART) and ERESTARTNOINTR. ERESTART_RESTARTBLOCK is
         * only supposed to be used for SIGSTOP help, and ERESTARTNOHAND never restarts if there is
         * a handler we're dispatching to (poll, pause, sigsuspend, etc) */
        switch (regs->rax)
        {
            case -ERESTARTSYS:
                if (!(ksa->sa_flags & SA_RESTART))
                {
                    regs->rax = -EINTR;
                    break;
                }
                /* fallthrough */
            case -ERESTARTNOINTR:
                regs->rax = regs->int_no;
                regs->rip -= 2;
                break;

            case -ERESTART_RESTARTBLOCK:
            case -ERESTARTNOHAND:
                regs->rax = -EINTR;
                break;
        }
    }

    if (signal_setup_context(sinfo->signum, &sinfo->info, ksa, regs) < 0)
    {
        signal_restore_sigmask();
        force_sigsegv(sinfo->signum);
        return;
    }

    signal_end_delivery(sinfo);
}

void handle_signal(struct registers *regs)
{
    struct arch_siginfo sinfo;
    /* We can't do signals while in kernel space */
    if (in_kernel_space_regs(regs))
        return;

    if (irq_is_disabled())
        irq_enable();

    if (find_signal(&sinfo))
    {
        deliver_signal(&sinfo, regs);
        return;
    }

    /* We didn't find a signal, and we're in a syscall. Restart ERESTARTSYS, ERESTARTNOHAND,
     * ERESTARTNOINTR and ERESTART_RESTARTBLOCK */
    if (in_syscall(regs))
    {
        switch (regs->rax)
        {
            case -ERESTARTNOHAND:
            case -ERESTARTNOINTR:
            case -ERESTARTSYS: {
                regs->rax = regs->int_no;
                regs->rip -= 2;
                break;
            }
                /* TODO: ERESTART_RESTARTBLOCK */
        }
    }

    signal_restore_sigmask();
}
