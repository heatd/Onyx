/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <string.h>

#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>

#include <uapi/clone.h>

extern void ret_from_fork_asm(void);

void ret_from_fork(void)
{
    /* We take care of everything that needs to be done post-fork on the child process (that we
     * couldn't really do beforehand) */
    if (current->set_tid)
        copy_to_user(current->set_tid, &current->pid_, sizeof(pid_t));
}

void thread_setup_stack(struct thread *thread, bool is_user, const registers_t *regs);

struct thread *process_fork_thread(thread_t *src, struct process *dest, unsigned int flags,
                                   unsigned long stack, unsigned long tls)
{
    registers_t regs;
    struct syscall_frame *ctx = task_curr_syscall_frame();
    unsigned long new_tls = src->tpidr;

    /* Setup the registers on the stack */
    memcpy(&regs, &ctx->regs, sizeof(regs));
    regs.x[0] = 0; // fork returns 0
    if (stack != 0)
        regs.sp = stack;
    if (flags & CLONE_SETTLS)
        new_tls = tls;

    thread_t *thread = sched_spawn_thread(&regs, 0, (void *) new_tls);
    if (!thread)
        return NULL;

    regs.pc = (unsigned long) &ret_from_fork_asm;
    thread_setup_stack(thread, false, &regs);
    save_fpu(thread->fpu_area);

    thread->owner = dest;
    thread->aspace = dest->address_space;
    dest->thr = thread;
    thread_get(thread);
    return thread;
}
