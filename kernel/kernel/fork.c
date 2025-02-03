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

void process_copy_current_sigmask(struct thread *dest)
{
    memcpy(&dest->sinfo.sigmask, &get_current_thread()->sinfo.sigmask, sizeof(sigset_t));
}

static int dup_files(struct process *child)
{
    return copy_file_descriptors(child, &current->ctx);
}

static int dup_fs(struct process *child)
{
    struct ioctx *ctx = &current->ctx;
    spin_lock(&ctx->cwd_lock);
    path_get(&ctx->cwd);
    path_get(&ctx->root);
    child->ctx.cwd = ctx->cwd;
    child->ctx.root = ctx->root;
    child->ctx.umask = READ_ONCE(ctx->umask);
    spin_unlock(&ctx->cwd_lock);
    return 0;
}

static int dup_sighand(struct process *child)
{
    int i;

    spin_lock(&current->signal_lock);
    for (i = 0; i < _NSIG; i++)
        child->sigtable[i] = current->sigtable[i];
    spin_unlock(&current->signal_lock);
    return 0;
}

static int dup_signal(struct process *child)
{
    int i;
    /* Note: We don't dupe pgrp, session and pgrp here, because we don't hold the tasklist_lock */
    write_lock(&current->rlimit_lock);
    for (i = 0; i < RLIM_NLIMITS + 1; i++)
        child->rlimits[i] = current->rlimits[i];
    write_unlock(&current->rlimit_lock);

    child->flags = current->flags;
    return 0;
}

static pid_t kernel_clone(struct clone_args *args)
{
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
        WARN_ON(1);
    else
        err = dup_files(child);
    if (err < 0)
        goto err_put_pid;

    if (flags & CLONE_FS)
        WARN_ON(1);
    else
        err = dup_fs(child);
    if (err < 0)
        goto err_put_files;

    if (flags & CLONE_SIGHAND)
        WARN_ON(1);
    else
        err = dup_sighand(child);

    if (err < 0)
        goto err_put_fs;

    if (flags & CLONE_THREAD)
        WARN_ON(1);
    else
        err = dup_signal(child);

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

    INIT_LIST_HEAD(&child->thread_list);

    /* Fork and create the new thread */
    struct thread *new_thread =
        process_fork_thread(to_be_forked, child, flags, args->stack, args->tls);
    if (!new_thread)
        goto err_put_mm;

    /* Inherit the parent process' properties */
    child->personality = current->personality;
    child->vdso = current->vdso;
    process_inherit_creds(child, current);

    child->image_base = current->image_base;
    child->interp_base = current->interp_base;

    /* Note that the signal mask is inherited at thread creation */
    /* Note that pending signals are zero'd, as per POSIX */

    write_lock(&tasklist_lock);

    process_append_children(current, child);

    child->parent = current;
    child->process_group = current->process_group;
    child->session = current->session;
    // Inherit the controlling terminal
    child->ctty = current->ctty;
    process_append_to_global_list(child);
    pid_add_process(child->process_group, child, PIDTYPE_PGRP);
    pid_add_process(child->session, child, PIDTYPE_SID);

    write_unlock(&tasklist_lock);

    child->flags |= PROCESS_FORKED;
    process_get(child);
    process_copy_current_sigmask(new_thread);

    struct vfork_completion vfork_cmpl;
    if (flags & CLONE_VFORK)
        child->vfork_compl = &vfork_cmpl;

    sched_start_thread(new_thread);

    if (flags & CLONE_VFORK)
    {
        // We wait for the vforked child to do its thing, and then we wait until its safe to exit
        // i.e the child has finished waking up waiters.
        vfork_compl_wait(&vfork_cmpl);
        vfork_compl_wait_to_exit(&vfork_cmpl);
    }

    // Return the pid to the caller
    pid_t pid = child->pid_;
    process_put(child);
    return pid;
err_put_mm:
    mmput(child->address_space);
err_put_signal:
err_put_fs:
err_put_files:
    panic("todo");
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
