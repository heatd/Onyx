/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define DEFINE_CURRENT
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <onyx/binfmt.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/dentry.h>
#include <onyx/elf.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/futex.h>
#include <onyx/mm/slab.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/pid.h>
#include <onyx/proc_event.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/seqlock.h>
#include <onyx/syscall.h>
#include <onyx/task_switching.h>
#include <onyx/thread.h>
#include <onyx/tty.h>
#include <onyx/user.h>
#include <onyx/utils.h>
#include <onyx/vdso.h>
#include <onyx/vfork_completion.h>
#include <onyx/worker.h>

#include <uapi/clone.h>

struct vfork_completion;

#define __user

struct clone_args
{
    unsigned int flags;
    int exit_signal;
    int __user *parent_tid;
    int __user *child_tid;
    unsigned long tls;
    unsigned long stack;
};

void process_copy_current_sigmask(struct process *dest)
{
    memcpy(&dest->sigmask, &current->sigmask, sizeof(sigset_t));
}

static void ioctx_init(struct ioctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->refs = REFCOUNT_INIT(1);
}

static int dup_files(struct process *child)
{
    int err;
    struct ioctx *ctx = kmalloc(sizeof(struct ioctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    ioctx_init(ctx);
    child->ctx = ctx;
    err = copy_file_descriptors(child, current->ctx);
    if (err)
    {
        kfree(ctx);
        return err;
    }

    return 0;
}

static int dup_fs(struct process *child)
{
    struct fsctx *fs = kmalloc(sizeof(*fs), GFP_KERNEL);
    if (!fs)
        return -ENOMEM;

    fsctx_init(fs);
    child->fs = fs;
    spin_lock(&current->fs->cwd_lock);
    path_get(&current->fs->cwd);
    path_get(&current->fs->root);
    child->fs->cwd = current->fs->cwd;
    child->fs->root = current->fs->root;
    child->fs->umask = READ_ONCE(current->fs->umask);
    spin_unlock(&current->fs->cwd_lock);
    return 0;
}

static int dup_sighand(struct process *child)
{
    int i;
    struct sighand_struct *sig = kmalloc(sizeof(*sig), GFP_KERNEL);
    if (!sig)
        return -ENOMEM;

    sighand_init(sig);
    child->sighand = sig;
    spin_lock(&current->sighand->signal_lock);
    for (i = 0; i < _NSIG; i++)
        child->sighand->sigtable[i] = current->sighand->sigtable[i];
    spin_unlock(&current->sighand->signal_lock);
    return 0;
}

static int dup_signal(struct process *child)
{
    int i;
    struct signal_struct *curr = current->sig;
    struct signal_struct *sig = kmalloc(sizeof(*sig), GFP_KERNEL);
    if (!sig)
        return -ENOMEM;

    sig->refs = REFCOUNT_INIT(1);
    sig->ctty = curr->ctty;
    sig->nr_threads = 1;
    sig->tgid = child->pid_struct;
    INIT_LIST_HEAD(&sig->thread_list);
    list_add_tail_rcu(&child->thread_list_node.__lh, &sig->thread_list);
    rwslock_init(&sig->rlimit_lock);
    sig->signal_group_flags = 0;
    sig->tg_leader = child;
    sig->group_notify_task = NULL;
    sig->group_notify_pending = 0;
    child->sig = sig;
    spin_lock_init(&sig->pgrp_lock);
    init_wait_queue_head(&sig->wait_child_event);
    sigqueue_init(&sig->shared_signals);
    seqlock_init(&sig->stats_lock);
    sig->cutime = sig->cstime = sig->stime = sig->utime = 0;
    sig->majflt = sig->minflt = sig->cmajflt = sig->cminflt = 0;
    sig->nivcsw = sig->nvcsw = sig->cnivcsw = sig->cnvcsw = 0;

    /* Note: We don't dupe pgrp, session and pgrp here, because we don't hold the tasklist_lock */
    read_lock(&curr->rlimit_lock);
    for (i = 0; i < RLIM_NLIMITS + 1; i++)
        sig->rlimits[i] = curr->rlimits[i];
    read_unlock(&curr->rlimit_lock);

    itimer_init(child);
    child->flags = current->flags;
    return 0;
}

static void free_signal(struct process *child)
{
    /* We need this special function to partially destroy the signal_struct, instead of exit_signal
     * which does not handle partially constructed signal_struct's properly.
     */
    struct signal_struct *sig = child->sig;
    kfree(sig);
}

static void process_append_children(struct process *parent, struct process *children)
{
    list_add_tail(&children->sibbling_node, &parent->children_head);
}

static pid_t kernel_clone(struct clone_args *args)
{
    pid_t pid;
    struct process *child;
    int err;
    thread_t *to_be_forked;
    unsigned int flags = args->flags;

    to_be_forked = get_current_thread();

    /* First, reject BS flag combinations */
    /* CLONE_THREAD implies CLONE_SIGHAND, and CLONE_SIGHAND implies CLONE_VM */
    if ((flags & (CLONE_SIGHAND | CLONE_VM)) == CLONE_SIGHAND)
        return -EINVAL;
    if ((flags & (CLONE_THREAD | CLONE_SIGHAND)) == CLONE_THREAD)
        return -EINVAL;

    /* Create a new process */

    child = process_alloc();
    if (!child)
        return -ENOMEM;

    child->pid_struct = pid_alloc(child);
    if (IS_ERR(child->pid_struct))
    {
        err = PTR_ERR(child->pid_struct);
        goto free_proc;
    }

    err = 0;
    if (flags & CLONE_FILES)
    {
        refcount_inc(&current->ctx->refs);
        child->ctx = current->ctx;
    }
    else
        err = dup_files(child);
    if (err < 0)
        goto err_put_pid;

    if (flags & CLONE_FS)
    {
        refcount_inc(&current->fs->refs);
        child->fs = current->fs;
    }
    else
        err = dup_fs(child);
    if (err < 0)
        goto err_put_files;

    if (flags & CLONE_SIGHAND)
    {
        child->sighand = current->sighand;
        refcount_inc(&child->sighand->refs);
    }
    else
        err = dup_sighand(child);

    if (err < 0)
        goto err_put_fs;

    if (flags & CLONE_THREAD)
    {
        child->sig = current->sig;
        refcount_inc(&child->sig->refs);
        /* More CLONE_THREAD handling done below, under the proper locks */
    }
    else
        err = dup_signal(child);
    if (err < 0)
        goto err_put_sighand;

    if (flags & CLONE_VM)
    {
        child->address_space = current->address_space;
        mmget(child->address_space);
    }
    else
    {
        child->address_space = mm_fork();
        if (IS_ERR(child->address_space))
            goto err_put_signal;
    }

    if (flags & CLONE_PARENT_SETTID)
    {
        err = copy_to_user(args->parent_tid, &child->pid_, sizeof(pid_t));
        if (err)
            goto err_put_mm;
    }

    /* Fork and create the new thread */
    struct thread *new_thread =
        process_fork_thread(to_be_forked, child, flags, args->stack, args->tls);
    if (!new_thread)
        goto err_put_mm;

    child->ctid = child->set_tid = NULL;
    if (flags & CLONE_CHILD_CLEARTID)
        child->ctid = args->child_tid;
    if (flags & CLONE_CHILD_SETTID)
        child->set_tid = args->child_tid;

    /* Inherit the parent process' properties */
    child->personality = current->personality;
    child->vdso = current->vdso;
    process_inherit_creds(child, current);

    child->image_base = current->image_base;
    child->interp_base = current->interp_base;

    /* Note that the signal mask is inherited at thread creation */
    /* Note that pending signals are zero'd, as per POSIX */

    write_lock(&tasklist_lock);
    spin_lock(&child->sighand->signal_lock);

    if (flags & (CLONE_THREAD | CLONE_PARENT))
    {
        /* Our parent (if CLONE_THREAD or CLONE_PARENT) is the current's parent. Regular UNIX
         * process parentage doesn't apply here. */
        child->parent = current->parent;
    }
    else
        child->parent = current;

    process_append_children(child->parent, child);
    process_append_to_global_list(child);

    if (flags & CLONE_THREAD)
    {
        /* Add ourselves to the list of threads */
        list_add_tail_rcu(&child->thread_list_node.__lh, &child->sig->thread_list);
        child->sig->nr_threads++;
    }
    else
    {
        struct pid *pgrp, *session;

        pgrp = task_pgrp_locked(current);
        session = task_session_locked(current);
        rcu_assign_pointer(child->sig->process_group, pgrp);
        rcu_assign_pointer(child->sig->session, session);
        // Inherit the controlling terminal
        child->sig->ctty = current->sig->ctty;
        pid_add_process(pgrp, child, PIDTYPE_PGRP);
        pid_add_process(session, child, PIDTYPE_SID);
    }

    spin_unlock(&child->sighand->signal_lock);
    write_unlock(&tasklist_lock);

    set_task_flag(child, PROCESS_FORKED);
    pid = child->pid_;
    process_copy_current_sigmask(child);

    /* If not sharing the same VM *concurrently* (vfork is ok), copy altstack */
    if ((flags & (CLONE_VFORK | CLONE_VM)) != CLONE_VM)
        child->altstack = current->altstack;
    else
        sigaltstack_init(&child->altstack);
    sigqueue_init(&child->sigqueue);

    struct vfork_completion vfork_cmpl;
    vfork_compl_init(&vfork_cmpl);
    if (flags & CLONE_VFORK)
        child->vfork_compl = &vfork_cmpl;

    /* Note: sched_start_thread already provides the necessary memory ordering wrt vfork or anything
     * else */
    sched_start_thread(new_thread);

    if (flags & CLONE_VFORK)
    {
        // We wait for the vforked child to do its thing, and then we wait until its safe to exit
        // i.e the child has finished waking up waiters.
        vfork_compl_wait(&vfork_cmpl);
        vfork_compl_wait_to_exit(&vfork_cmpl);
    }

    return pid;
err_put_mm:
    mmput(child->address_space);
err_put_signal:
    free_signal(child);
err_put_sighand:
    exit_sighand(child);
err_put_fs:
    exit_fs(child);
err_put_files:
    exit_files(child);
err_put_pid:
    put_pid(child->pid_struct);
free_proc:
    kfree(child);
    return err;
}

pid_t sys_fork(struct syscall_frame *ctx)
{
    struct clone_args args = {
        .exit_signal = SIGCHLD,
    };

    return kernel_clone(&args);
}

pid_t sys_vfork(struct syscall_frame *ctx)
{
    struct clone_args args = {
        .exit_signal = SIGCHLD,
        .flags = CLONE_VM | CLONE_VFORK,
    };

    return kernel_clone(&args);
}

#ifdef CONFIG_CLONE_BACKWARDS
int sys_newclone(unsigned long clone_flags, unsigned long newsp, int __user *parent_tidptr,
                 unsigned long tls, int __user *child_tidptr)
#elif defined(CONFIG_CLONE_BACKWARDS2)
int sys_newclone(unsigned long newsp, unsigned long clone_flags, int __user *parent_tidptr,
                 int __user *child_tidptr, unsigned long tls)
#elif defined(CONFIG_CLONE_BACKWARDS3)
int sys_newclone(unsigned long clone_flags, unsigned long newsp, int stack_size,
                 int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls)
#else
int sys_newclone(unsigned long clone_flags, unsigned long newsp, int __user *parent_tidptr,
                 int __user *child_tidptr, unsigned long tls)
#endif
{
    struct clone_args args = {
        .flags = (((u32) clone_flags) & ~CSIGNAL),
        .child_tid = child_tidptr,
        .parent_tid = parent_tidptr,
        .exit_signal = clone_flags & CSIGNAL,
        .stack = newsp,
        .tls = tls,
    };

    return kernel_clone(&args);
}
