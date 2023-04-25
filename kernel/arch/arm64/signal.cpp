/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>

#include <onyx/arm64/fpu.h>
#include <onyx/arm64/signal.h>
#include <onyx/signal.h>
#include <onyx/thread.h>
#include <onyx/vm.h>

#include <uapi/signal.h>

/* Linux arm64 signal contexts are laid out in a sort of extensible list with tag types.
 * Each item starts with a _aarch64_ctx {magic, size}, and then item specific data (FPU, ESR_EL1,
 * etc). The list then ends in a null entry {magic = 0, size = 0}.
 */

struct sigcontext_context
{
    struct sigframe *sframe;
    u8 *ctx_start;
    u8 *ctx_tail;

    sigcontext_context(struct sigframe *sframe) : sframe{sframe}
    {
        ctx_start = ctx_tail = sframe->uc.uc_mcontext.__reserved;
    }

    int write_gprs(struct registers *regs);

    template <typename Callable>
    int write_ctx(unsigned int magic, unsigned int len, Callable writer)
    {
        auto to_write = ctx_tail;
        ctx_tail += len;

        _aarch64_ctx ctx;
        ctx.magic = magic;
        ctx.size = len;

        // Write the head first, since all context bits start with it
        if (copy_to_user(to_write, &ctx, sizeof(ctx)) < 0)
            return -EFAULT;

        return writer(to_write);
    }

    int terminate()
    {
        // The list ends with a null _aarch64_ctx (magic = 0, size = 0).
        return write_ctx(0, 0, [](u8 *) -> int { return 0; });
    }
};

int sigcontext_context::write_gprs(struct registers *regs)
{
    // Turns out struct registers's layout == sigcontext
    return copy_to_user(sframe->uc.uc_mcontext.regs, regs, sizeof(*regs));
}

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

    /* Start setting the register state for the register switch */
    /* Note that we're saving the old ones */

    /* We need a 16 byte aligned location here, as the stack will point here */
    unsigned long sframe_location = sp - sizeof(struct sigframe);
    sframe_location &= -16;

    struct sigframe *sframe = (struct sigframe *) sframe_location;

    if (k_sigaction->sa_flags & SA_SIGINFO)
    {
        if (copy_to_user(&sframe->sinfo, pend->info, sizeof(siginfo_t)) < 0)
            return -EFAULT;
    }

    sigcontext_context ctx{sframe};

    /* Set-up the ucontext */
    if (ctx.write_gprs(regs) < 0)
        return -EFAULT;

    /* We're saving the sigmask, that will then be restored */
    auto mask = curr->sinfo.flags & THREAD_SIGNAL_ORIGINAL_SIGSET ? &curr->sinfo.original_sigset
                                                                  : &curr->sinfo.sigmask;
    curr->sinfo.flags &= ~THREAD_SIGNAL_ORIGINAL_SIGSET;
    if (copy_to_user(&sframe->uc.uc_sigmask, mask, sizeof(sigset_t)) < 0)
        return -EFAULT;

    save_fpu(curr->fpu_area);

    // TODO(pedro): Find a nice way to pass ESR and fault_address

    if (user_memset(&sframe->uc.uc_mcontext.fault_address, 0, sizeof(unsigned long)) < 0)
        return -EFAULT;

    int st = ctx.write_ctx(FPSIMD_MAGIC, sizeof(fpsimd_context), [curr](u8 *uptr) -> int {
        struct fpstate *state = (struct fpstate *) curr->fpu_area;
        fpsimd_context *uctx = (fpsimd_context *) uptr;

        // Our fpstate struct is laid out {fpregs, fpsr, fpcr}, while fpsimd_context is laid out
        // {fpsr, fpcr, fpregs}.
        if (copy_to_user(&uctx->fpsr, &state->fpsr, sizeof(u32) * 2) < 0)
            return -EFAULT;

        static_assert(sizeof(uctx->vregs) == sizeof(state->regs),
                      "fpsimd_context regs size != fpstate regs size");

        return copy_to_user(uctx->vregs, state->regs, sizeof(state->regs));
    });

    if (st < 0)
        return st;

    if (st = ctx.terminate(); st < 0)
        return st;

    // It should be 16 bytes aligned
    assert((sframe_location & 0xf) == 0);

    regs->sp = sframe_location;
    regs->pc = (unsigned long) k_sigaction->sa_handler;
    regs->x[0] = sig;
    regs->x[30] = (unsigned long) k_sigaction->sa_restorer;

    if (k_sigaction->sa_flags & SA_SIGINFO)
    {
        regs->x[1] = (unsigned long) &sframe->sinfo;
        regs->x[2] = (unsigned long) &sframe->uc;
    }

    return 0;
}

static int restore_fpsimd(const u8 *userptr)
{
    auto curr = get_current_thread();
    fpsimd_context ctx;

    if (copy_from_user(&ctx, userptr, sizeof(ctx)) < 0)
        return -EFAULT;

    irq_disable();

    auto fpuarea = (fpstate *) curr->fpu_area;
    fpuarea->fpcr = ctx.fpcr;
    fpuarea->fpsr = ctx.fpsr;
    memcpy(fpuarea->regs, ctx.vregs, sizeof(fpuarea->regs));

    restore_fpu(curr->fpu_area);

    irq_enable();

    return 0;
}

static int restore_item(const u8 *userptr, const _aarch64_ctx &header)
{
    switch (header.magic)
    {
        case FPSIMD_MAGIC: {
            if (header.size != sizeof(fpsimd_context))
                return -EINVAL;
            return restore_fpsimd(userptr);
        }

        // ESR_MAGIC is not restoreable
        case ESR_MAGIC:
            return 0;
        // Bad header (we most certainly did not write this)
        default:
            return -EINVAL;
    }
}

static int restore_extra(sigcontext *ctx)
{
    const u8 *u = ctx->__reserved;

    for (;;)
    {
        _aarch64_ctx header;
        if (copy_from_user(&header, u, sizeof(header)) < 0)
            return -EFAULT;

        if (header.magic == 0 && header.size == 0)
            return 0;

        // Reject bad headers
        if (header.size == 0 || header.size >= sizeof(ctx->__reserved))
            return -EINVAL;

        if (u + header.size >= ctx->__reserved + sizeof(ctx->__reserved))
            return -EINVAL;

        if (int st = restore_item(u, header); st < 0)
            return st;

        u += header.size;
    }
}

unsigned long sys_sigreturn(registers *frame)
{
    registers regs;
    /* Switch the registers again */
    struct sigframe *sframe = (struct sigframe *) frame->sp;

    // TODO(pedro): Linux seems to think that raising SIGSEGV is better than returning an error code
    // (FreeBSD does this, according to the manpage). Think about this.

    if (copy_from_user(&regs, &sframe->uc.uc_mcontext.regs, sizeof(registers)) < 0)
        return -EFAULT;

    if (regs.pstate & 0b1111)
    {
        // User tried to change pstate's EL, EINVAL
        return -EINVAL;
    }

    struct thread *curr = get_current_thread();

    /* Restore the old sigmask */
    sigset_t set;
    if (copy_from_user(&set, &sframe->uc.uc_sigmask, sizeof(set)) < 0)
        return -EFAULT;

    if (int st = restore_extra(&sframe->uc.uc_mcontext); st < 0)
        return st;

    curr->sinfo.set_blocked(&set);

    memcpy(frame, &regs, sizeof(regs));

    return frame->x[0];
}
