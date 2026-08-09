/*
 * Copyright (c) 2017 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <stdbool.h>
#include <sys/ptrace.h>

#include <onyx/fpu.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/ptrace.h>
#include <onyx/types.h>
#include <onyx/vm.h>

#include <uapi/user.h>

int ptrace_peek(struct process *process, void *addr, ptrace_word_t *word)
{
    return errno = EFAULT, -1;
}

int ptrace_poke(struct process *process, void *addr, ptrace_word_t word)
{
    return errno = EFAULT, -1;
}

long ptrace_peekuser(struct process *process, unsigned long addr, unsigned long *data)
{
    struct registers *regs = task_regs(process);
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
    user.fs_base = (unsigned long) process->thr->fs;
    user.gs_base = (unsigned long) process->thr->gs;
    user.orig_rax = regs->int_no;

    if (addr & (sizeof(unsigned long) - 1) || addr >= sizeof(user))
        return -EIO;
    return copy_to_user(data, ((u8 *) &user) + addr, sizeof(unsigned long));
}

long arch_ptrace(long request, struct process *task, unsigned long addr, unsigned long data,
                 unsigned long addr2)
{
    switch (request)
    {
        case PTRACE_PEEKUSER:
            return ptrace_peekuser(task, addr, (unsigned long *) data);
        case PTRACE_PEEKDATA:
        case PTRACE_PEEKTEXT:
        case PTRACE_POKEDATA:
        case PTRACE_POKETEXT: {
            struct iovec iov = {
                .iov_base = (void *) data,
                .iov_len = sizeof(unsigned long),
            };
            struct iovec_iter iter;
            ssize_t err;
            iovec_iter_init_uiov(&iter, &iov, 1, sizeof(unsigned long));
            err = access_remote_mm(task->address_space, addr, &iter,
                                   (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT));
            if (err != sizeof(unsigned long))
                err = -EIO;
            return err;
        }
    }

    return -EINVAL;
}
