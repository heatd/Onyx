/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <errno.h>

#include <onyx/process.h>
#include <onyx/riscv/signal.h>
#include <onyx/signal.h>
#include <onyx/thread.h>
#include <onyx/vm.h>

#include <uapi/signal.h>

int signal_setup_context(int sig, siginfo_t *siginfo, struct k_sigaction *k_sigaction,
                         struct registers *regs)
{
    struct thread *curr = get_current_thread();
    unsigned long sp = regs->sp;
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
    unsigned long sframe_location = sp - sizeof(struct sigframe);
    sframe_location &= -16;

    struct sigframe *sframe = (struct sigframe *) sframe_location;

    __riscv_mc_gp_state state;

    if (k_sigaction->sa_flags & SA_SIGINFO)
    {
        if (copy_to_user(&sframe->sinfo, siginfo, sizeof(siginfo_t)) < 0)
            return -EFAULT;
    }

    /* Set-up the ucontext */
    /* Note that state[0] does not mean x0 but rather pc */
    memcpy(&state[1], regs->gpr, sizeof(unsigned long) * 31);
    state[0] = regs->epc;

    if (copy_to_user(&sframe->uc.uc_mcontext.__gregs, state, sizeof(state)) < 0)
        return -EFAULT;

    /* We're saving the sigmask, that will then be restored */
    sigset_t *mask =
        test_task_flag(current, TF_RESTORE_SIGMASK) ? &current->original_sigset : &current->sigmask;
    clear_task_flag(current, TF_RESTORE_SIGMASK);
    if (copy_to_user(&sframe->uc.uc_sigmask, mask, sizeof(sigset_t)) < 0)
        return -EFAULT;

    save_fpu(curr->fpu_area);

    if (copy_to_user(&sframe->uc.uc_mcontext.__fpregs, curr->fpu_area, fpu_size) < 0)
        return -EFAULT;

    // It should be 16 bytes aligned
    assert((sframe_location & 0xf) == 0);

    regs->sp = sframe_location;
    regs->epc = (unsigned long) k_sigaction->sa_handler;
    regs->a0 = sig;
    regs->ra = (unsigned long) k_sigaction->sa_restorer;

    if (k_sigaction->sa_flags & SA_SIGINFO)
    {
        regs->a1 = (unsigned long) &sframe->sinfo;
        regs->a2 = (unsigned long) &sframe->uc;
    }

    return 0;
}

unsigned long sys_sigreturn(registers *frame)
{
    /* Switch the registers again */
    __riscv_mc_gp_state state;
    __riscv_mc_fp_state fpstate;

    struct sigframe *sframe = (struct sigframe *) frame->sp;

    if (copy_from_user(state, &sframe->uc.uc_mcontext.__gregs, sizeof(state)) < 0)
        return -EFAULT;

    struct thread *curr = get_current_thread();

    /* Restore the old sigmask */
    sigset_t set;
    if (copy_from_user(&set, &sframe->uc.uc_sigmask, sizeof(set)) < 0)
        return -EFAULT;

    /* We need to disable interrupts here to avoid corruption of the fpu state */

    if (copy_from_user(&fpstate, &sframe->uc.uc_mcontext.__fpregs, fpu_get_save_size()) < 0)
        return -EFAULT;

    irq_disable();
    memcpy(curr->fpu_area, &fpstate, fpu_get_save_size());
    restore_fpu(curr->fpu_area);
    irq_enable();

    signal_setmask(&set);
    /* Finally, restore the GPRs */
    frame->epc =
        state[0] - 4; /* We de-offset the epc so the trap return code does that again for us */
    memcpy(frame->gpr, &state[1], sizeof(unsigned long) * 31);

    return frame->a0;
}

static bool in_syscall(struct registers *regs)
{
    bool is_exception = !(regs->cause & RISCV_SCAUSE_INTERRUPT);
    unsigned long cause = regs->cause & ~RISCV_SCAUSE_INTERRUPT;
    return is_exception && cause == 8;
}

static void deliver_signal(struct arch_siginfo *sinfo, struct registers *regs)
{
    struct k_sigaction *ksa = &sinfo->action;
    if (in_syscall(regs))
    {
        /* Only restart ERESTARTSYS (if SA_RESTART) and ERESTARTNOINTR. ERESTART_RESTARTBLOCK is
         * only supposed to be used for SIGSTOP help, and ERESTARTNOHAND never restarts if there is
         * a handler we're dispatching to (poll, pause, sigsuspend, etc) */
        switch ((long) regs->a0)
        {
            case -ERESTARTSYS:
                if (!(ksa->sa_flags & SA_RESTART))
                {
                    regs->a0 = -EINTR;
                    break;
                }
                /* fallthrough */
            case -ERESTARTNOINTR:
                regs->a0 = regs->orig_a0;
                regs->epc -= 4;
                break;

            case -ERESTART_RESTARTBLOCK:
            case -ERESTARTNOHAND:
                regs->a0 = -EINTR;
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
        switch ((long) regs->a0)
        {
            case -ERESTARTNOHAND:
            case -ERESTARTNOINTR:
            case -ERESTARTSYS: {
                regs->a0 = regs->orig_a0;
                regs->epc -= 4;
                break;
            }
                /* TODO: ERESTART_RESTARTBLOCK */
        }
    }

    signal_restore_sigmask();
}
