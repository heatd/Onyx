/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <errno.h>

#include <onyx/elf.h>
#include <onyx/err.h>
#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>
#include <onyx/x86/shadow_stack.h>

#include <uapi/clone.h>

namespace x86::internal
{
void thread_setup_stack(thread *thread, bool is_user, registers_t *regs);
}

extern "C" void ret_from_fork(void)
{
    /* We take care of everything that needs to be done post-fork on the child process (that we
     * couldn't really do beforehand) */
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

    if (src->shadow_stack)
    {
        /* If the two tasks are sharing address spaces, make them create their own shadow stack. An
         * edge case is CLONE_VFORK, which wants to share the parent's shadow stack state. The libc
         * knows this and is adapted for it.
         */
        if ((flags & (CLONE_VM | CLONE_VFORK)) == CLONE_VM)
        {
            if (shstk_clone_thread(thread, src) < 0)
            {
                thread_put(thread);
                return nullptr;
            }
        }
        else
        {
            thread->shadow_stack = (void *) rdmsr(IA32_PL3_SSP);
            /* When sharing an MM, _do not_ try to unmap it at exit. That leads to stuff like
             * vfork() + _exit() destroying the parent's shadow stack. */
            if (flags & CLONE_VM)
            {
                thread->shadow_stack_base = NULL;
                thread->shadow_stack_size = 0;
            }
            else
            {
                thread->shadow_stack_base = src->shadow_stack_base;
                thread->shadow_stack_size = src->shadow_stack_size;
            }
            thread->shstk_state = src->shstk_state;
        }
    }

    thread->task_affinity = task_curr_affinity();
    save_fpu(thread->fpu_area);

    thread->owner = dest;
    thread->set_aspace(dest->get_aspace());
    dest->thr = thread;
    thread_get(thread);
    return thread;
}

int process_alloc_stack(struct stack_info *info)
{
    info->base = (void *) vm_pick_stack_location();
    void *ptr = vm_mmap(info->base, info->length, PROT_WRITE | PROT_READ,
                        MAP_ANON | MAP_PRIVATE | MAP_FIXED | MAP_GROWSDOWN, nullptr, 0);
    if (IS_ERR(ptr))
        return PTR_ERR(ptr);
    CHECK(ptr == info->base);
    info->top = reinterpret_cast<void *>((unsigned long) ptr + info->length);

    return 0;
}

int sys_clone(void *fn, void *child_stack, int flags, void *arg, struct tid_out *out, void *tls)
{
    return -ENOSYS;
}

void core_fill_regs(elf_gregset_t *set, struct process *thread)
{
    /* thread is alive and suspended (or is us. either way, task_regs will work ) */
    struct registers *regs = task_regs(thread);
    struct user_regs_struct user;

    user.rax = regs->rax;
    user.rbx = regs->rbx;
    user.rcx = regs->rcx;
    user.rdx = regs->rdx;
    user.rdi = regs->rdi;
    user.rsi = regs->rsi;
    user.rbp = regs->rbp;
    user.rip = regs->rip;
    user.r8 = regs->r8;
    user.r9 = regs->r9;
    user.r10 = regs->r10;
    user.r11 = regs->r11;
    user.r12 = regs->r12;
    user.r13 = regs->r13;
    user.r14 = regs->r14;
    user.r15 = regs->r15;
    user.cs = regs->cs;
    user.eflags = regs->rflags;
    user.rsp = regs->rsp;
    user.ds = user.ss = user.es = user.fs = user.gs = regs->ss;
    user.fs_base = (unsigned long) thread->thr->fs;
    user.gs_base = (unsigned long) thread->thr->gs;
    user.orig_rax = regs->int_no; /* XXX not sure how we should be meaningfully filling out... */

    static_assert(sizeof(elf_gregset_t) == sizeof(user),
                  "elf_gregset_t's layout needs to match user_regs_struct");
    memcpy(set, &user, sizeof(user));
}

void prepare_execve_exit(void *entry, void *stack)
{
    struct registers *regs = task_regs(current);

    if (current->thr->shstk_state || current->thr->shadow_stack_base)
        shstk_clear();

    memset(regs, 0, sizeof(*regs));
    regs->rsp = (unsigned long) stack;
    regs->rip = (unsigned long) entry;
    regs->cs = USER_CS;
    regs->ds = regs->ss = USER_DS;
    regs->rflags = default_rflags;
}
