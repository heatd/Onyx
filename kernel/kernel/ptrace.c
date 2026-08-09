/*
 * Copyright (c) 2017 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

#include <onyx/process.h>
#include <onyx/ptrace.h>

#include <uapi/user.h>

static void ptrace_add_traced(struct process *parent, struct process *child)
{
    list_add_tail(&child->ptrace_node, &parent->ptraced);
}

static void ptrace_detach(struct process *traced)
{
    /* For now, very simple. */
    list_remove(&traced->ptrace_node);
}

void exit_ptrace(void)
{
    struct process *traced, *next;

    /* Detach all traced children */
    // lockdep_tasklist_lock_held_write();
    list_for_each_entry_safe (traced, next, &current->ptraced, ptrace_node)
        ptrace_detach(traced);
}

static int ptrace_traceme(void)
{
    int err = -EPERM;

    /* tasklist_lock excludes against other tracers and exiting processes. */
    write_lock(&tasklist_lock);
    if (!current->tracer)
    {
        rcu_assign_pointer(current->tracer, current->parent);
        ptrace_add_traced(current->tracer, current);
        err = 0;
    }
    write_unlock(&tasklist_lock);
    return err;
}

static long ptrace_check_trace(struct process *task)
{
    long err;

    spin_lock(&task->sighand->signal_lock);
    err = -EPERM;
    /* Check if we're tracing the task */
    if (rcu_access_pointer(task->tracer) != current)
        goto out;
    /* Check if it's in a traced status */
    if (READ_ONCE(task->thr->status) == THREAD_TRACED)
        err = 0;
    /* Pairs with __ptrace_stop() */
    smp_rmb();
out:
    spin_unlock(&task->sighand->signal_lock);
    return err;
}

#define PT_O_MASK (PTRACE_O_TRACESYSGOOD)

static int ptrace_setoptions(struct process *task, unsigned long data)
{
    if (data & ~PT_O_MASK)
        return -EINVAL;

    task->ptrace_flags &= ~PT_O_MASK;
    task->ptrace_flags |= data;
    return 0;
}

int __ptrace_stop(int code, unsigned long message, siginfo_t *info)
{
    /* Set ptrace information and suspend. */
    current->exit_code = code;
    current->ptrace_message = message;
    current->ptrace_siginfo = info;

    /* Pairs with ptrace_check_trace() & co. Tracers must observe the metadata if they observe
     * TRACED. */
    smp_wmb();
    set_current_state(THREAD_TRACED);
    spin_unlock(&current->sighand->signal_lock);

    read_lock(&tasklist_lock);
    notify_process_stop_cont(current, CLD_TRAPPED);
    read_unlock(&tasklist_lock);
    /* The task is traced (or was woken up), tracer was woken up/signalled. Try and have some
     * sleep... */
    sched_yield();
    spin_lock(&current->sighand->signal_lock);
    current->ptrace_siginfo = NULL;
    return current->exit_code;
}

void ptrace_syscall(void)
{
    int sig = SIGTRAP;
    siginfo_t info;

    spin_lock(&current->sighand->signal_lock);
    if (current->ptrace_flags & PTRACE_O_TRACESYSGOOD)
        sig |= 0x80;
    sig = __ptrace_stop(sig, 0, NULL);
    if (sig == 0)
    {
        spin_unlock(&current->sighand->signal_lock);
        return;
    }

    memset(&info, 0, sizeof(info));
    rcu_read_lock();
    info.si_code = SI_USER;
    info.si_signo = sig;
    /* XXX what if tracer goes away? like on a detach. */
    info.si_pid = task_tgid(rcu_dereference(current->tracer));
    info.si_uid = rcu_dereference(current->tracer)->cred.euid;
    rcu_read_unlock();
    spin_unlock(&current->sighand->signal_lock);
    kernel_raise_signal(sig, current, 0, &info);
}

static bool is_valid_signal(int sig)
{
    return sig >= 0 && sig < NSIG;
}

static int ptrace_cont(struct process *task, long request, unsigned long data)
{
    if (!is_valid_signal(data))
        return -EINVAL;

    if (request == PTRACE_SYSCALL)
    {
        /* Next time this task hits syscall enter or exit, it will trigger extra work. */
        set_task_flag(task, TF_SYSCALL_WORK);
    }

    task->exit_code = data;

    /* Not supposed to fail. */
    WARN_ON(!thread_wake_up_try(task->thr, THREAD_TRACED, 0));
    return 0;
}

long sys_ptrace(long request, pid_t pid, void *addr, void *data, void *addr2)
{
    struct process *task;
    long err;

    if (request == PTRACE_TRACEME)
        return ptrace_traceme();
    task = get_process_from_pid(pid);
    if (!task)
        return -ESRCH;

    err = ptrace_check_trace(task);
    if (err)
        goto out;

    switch (request)
    {
        case PTRACE_SETOPTIONS:
            err = ptrace_setoptions(task, (unsigned long) data);
            break;
        case PTRACE_CONT:
        case PTRACE_SYSCALL:
            err = ptrace_cont(task, request, (unsigned long) data);
            break;
        default:
            err = arch_ptrace(request, task, (unsigned long) addr, (unsigned long) data,
                              (unsigned long) addr2);
            break;
    }
out:
    process_put(task);
    return err;
}
