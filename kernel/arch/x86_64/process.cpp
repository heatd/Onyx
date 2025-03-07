/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>

#include <onyx/err.h>
#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>

#include <uapi/clone.h>

namespace x86::internal
{
void thread_setup_stack(thread *thread, bool is_user, registers_t *regs);
}

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
    unsigned long rsp, rflags, ip;

    rsp = stack;
    if (stack == 0)
        rsp = ctx->rsp;
    rflags = ctx->rflags;
    ip = ctx->rip;

    /* Setup the registers on the stack */
    regs.rax = 0;
    regs.rbx = ctx->rbx;
    regs.rcx = 0;
    regs.rdx = ctx->rdx;
    regs.rdi = ctx->rdi;
    regs.rsi = ctx->rsi;
    regs.rbp = ctx->rbp;
    regs.rsp = rsp;
    regs.rip = ip;
    regs.r8 = ctx->r8;
    regs.r9 = ctx->r9;
    regs.r10 = ctx->r10;
    regs.r11 = 0;
    regs.r12 = ctx->r12;
    regs.r13 = ctx->r13;
    regs.r14 = ctx->r14;
    regs.r15 = ctx->r15;
    regs.rflags = rflags;

    thread_t *thread = sched_spawn_thread(&regs, 0, src->fs);
    if (!thread)
        return nullptr;

    if (flags & CLONE_SETTLS)
        thread->fs = (void *) tls;

    regs.rip = (unsigned long) &ret_from_fork_asm;
    x86::internal::thread_setup_stack(thread, false, &regs);

    save_fpu(thread->fpu_area);

    thread->owner = dest;
    thread->set_aspace(dest->get_aspace());
    dest->thr = thread;
    return thread;
}

int process_alloc_stack(struct stack_info *info)
{
    void *ptr =
        vm_mmap(nullptr, info->length, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, nullptr, 0);
    if (IS_ERR(ptr))
        return PTR_ERR(ptr);
    info->base = ptr;
    info->top = reinterpret_cast<void *>((unsigned long) ptr + info->length);

    return 0;
}

int sys_clone(void *fn, void *child_stack, int flags, void *arg, struct tid_out *out, void *tls)
{
    return -ENOSYS;
}
