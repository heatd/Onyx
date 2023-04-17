/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <uapi/signal.h>

#include <onyx/riscv/signal.h>
#include <onyx/signal.h>
#include <onyx/thread.h>
#include <onyx/vm.h>

#include <uapi/signal.h>

int signal_setup_context(struct sigpending *pend, struct k_sigaction *k_sigaction,
                         struct registers *regs)
{
    int sig = pend->signum;
    struct thread *curr = get_current_thread();
    struct signal_info *sinfo = &curr->sinfo;
    unsigned long sp = regs->sp;

    if (k_sigaction->sa_flags & SA_ONSTACK && !(sinfo->altstack.ss_flags & SS_DISABLE))
    {
        sp = (unsigned long) sinfo->altstack.ss_sp + sinfo->altstack.ss_size;
        if (sinfo->altstack.ss_flags & SS_AUTODISARM)
        {
            sinfo->altstack.ss_sp = nullptr;
            sinfo->altstack.ss_size = 0;
            sinfo->altstack.ss_flags = SS_DISABLE;
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
        if (copy_to_user(&sframe->sinfo, pend->info, sizeof(siginfo_t)) < 0)
            return -EFAULT;
    }

    /* Set-up the ucontext */
    /* Note that state[0] does not mean x0 but rather pc */
    memcpy(&state[1], regs->gpr, sizeof(unsigned long) * 31);
    state[0] = regs->epc;

    if (copy_to_user(&sframe->uc.uc_mcontext.__gregs, state, sizeof(state)) < 0)
        return -EFAULT;

    /* We're saving the sigmask, that will then be restored */
    auto mask = curr->sinfo.flags & THREAD_SIGNAL_ORIGINAL_SIGSET ? &curr->sinfo.original_sigset
                                                                  : &curr->sinfo.sigmask;
    curr->sinfo.flags &= ~THREAD_SIGNAL_ORIGINAL_SIGSET;
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

    curr->sinfo.set_blocked(&set);

    /* Finally, restore the GPRs */
    frame->epc =
        state[0] - 4; /* We de-offset the epc so the trap return code does that again for us */
    memcpy(frame->gpr, &state[1], sizeof(unsigned long) * 31);

    return frame->a0;
}
