/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>

#include <onyx/elf.h>
#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>

#include <uapi/clone.h>

namespace riscv::internal
{
void thread_setup_stack(thread *thread, bool is_user, const registers_t *regs);
} // namespace riscv::internal

extern "C" void ret_from_fork_asm(void);

extern "C" void ret_from_fork(void)
{
    /* We take care of everything that needs to be done post-fork on the child process (that we
     * couldn't really do beforehand) */
    struct process *current = get_current_process();
    if (current->set_tid)
        copy_to_user(current->set_tid, &current->pid_, sizeof(pid_t));
}

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

    regs.epc = (unsigned long) &ret_from_fork_asm;
    riscv::internal::thread_setup_stack(thread, false, &regs);
    save_fpu(thread->fpu_area);

    thread->owner = dest;
    thread->set_aspace(dest->get_aspace());
    dest->thr = thread;
    thread_get(thread);
    return thread;
}

int sys_clone(void *fn, void *child_stack, int flags, void *arg, struct tid_out *out, void *tls)
{
    return -ENOSYS;
}

void core_fill_regs(elf_gregset_t *set, struct process *thread)
{
    /* thread is alive and suspended (or is us. either way, task_regs will work ) */
    struct registers *regs = task_regs(thread);
    memcpy(&set->ra, &regs->gpr, sizeof(regs->gpr));
    set->pc = regs->epc;
}
