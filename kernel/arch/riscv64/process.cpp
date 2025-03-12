/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>

#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>

#include <uapi/clone.h>

struct thread *process_fork_thread(thread_t *src, struct process *dest, unsigned int flags,
                                   unsigned long stack, unsigned long tls)
{
    struct syscall_frame *ctx = task_curr_syscall_frame();
    registers_t regs;

    /* Setup the registers on the stack */
    memcpy(&regs, &ctx->regs, sizeof(regs));
    regs.a0 = 0;   // fork returns 0
    regs.epc += 4; // Skip the "ecall"
    if (stack != 0)
        regs.sp = stack;
    if (flags & CLONE_SETTLS)
        regs.tp = tls;

    thread_t *thread = sched_spawn_thread(&regs, 0, src->tp);
    if (!thread)
        return nullptr;

    save_fpu(thread->fpu_area);

    thread->owner = dest;
    thread->set_aspace(dest->get_aspace());

    list_add_tail(&thread->thread_list_head, &dest->thread_list);

    dest->nr_threads = 1;

    return thread;
}

#define CLONE_FORK        (1 << 0)
#define CLONE_SPAWNTHREAD (1 << 1)
long valid_flags = CLONE_FORK | CLONE_SPAWNTHREAD;

struct tid_out
{
    /* TID is placed here */
    pid_t *ptid;
    /* This location is zero'd when the thread exits */
    pid_t *ctid;
};

/* Hmmm, I don't think this is 100% correct but it's good enough */
static void inherit_signal_flags(thread *newt)
{
    auto current_thread = get_current_thread();

    scoped_lock g{current_thread->sinfo.lock};
    scoped_lock g2{newt->sinfo.lock};

    newt->sinfo.flags |= current_thread->sinfo.flags;
    newt->sinfo.__update_pending();
}

int sys_clone(void *fn, void *child_stack, int flags, void *arg, struct tid_out *out, void *tls)
{
    struct tid_out ktid_out;
    if (copy_from_user(&ktid_out, out, sizeof(ktid_out)) < 0)
        return -EFAULT;

    if (flags & ~valid_flags)
        return -EINVAL;
    if (flags & CLONE_FORK)
        return -EINVAL; /* TODO: Add CLONE_FORK */
    thread_callback_t start = (thread_callback_t) fn;

    registers_t regs = {};
    regs.sp = (unsigned long) child_stack;
    regs.status = RISCV_SSTATUS_SPIE;
    regs.epc = (unsigned long) start;
    regs.a0 = (unsigned long) arg;
    regs.tp = (unsigned long) tls;

    thread_t *thread = sched_spawn_thread(&regs, 0, tls);
    if (!thread)
        return -errno;

    if (copy_to_user(ktid_out.ptid, &thread->id, sizeof(pid_t)) < 0)
    {
        thread_destroy(thread);
        return -errno;
    }

    thread->ctid = ktid_out.ctid;

    process_add_thread(get_current_process(), thread);
    inherit_signal_flags(thread);
    sched_start_thread(thread);

    return 0;
}
