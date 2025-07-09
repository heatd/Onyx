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

void exit_fs(struct process *p)
{
    spin_lock(&p->alloc_lock);
    struct fsctx *fs = p->fs;
    p->fs = NULL;
    spin_unlock(&p->alloc_lock);
    if (refcount_dec_and_test(&fs->refs))
    {
        path_put(&fs->root);
        path_put(&fs->cwd);
        kfree(fs);
    }
}

void exit_sighand(struct process *p)
{
    struct sighand_struct *s = p->sighand;
    if (refcount_dec_and_test(&s->refs))
        kfree(s);
}

static void exit_mmap(void)
{
    struct mm_address_space *mm = current->address_space;
    spin_lock(&current->alloc_lock);
    current->address_space = &kernel_address_space;
    spin_unlock(&current->alloc_lock);
    vm_set_aspace(&kernel_address_space);
    mmput(mm);
}

static struct process *reaper_process(struct process *task) REQUIRES(tasklist_lock)
{
    struct process *thread;
    struct process *reaper = first_process;
    /* Look for any internal thread group member that can we can reparent to, first */
    for_each_thread (task, thread)
    {
        /* Skip exiting threads. They might be apart of a group exit, or maybe just us. */
        if (task->flags & PROCESS_EXITING)
            continue;
        reaper = thread;
        break;
    }

    /* If no internal thread group member has been found, default to pid 1 */
    return reaper;
}

static void kill_orphaned_pgrp(struct process *proc)
{
    struct pid *pgrp = task_pgrp_locked(proc);

    if (pid_is_orphaned_and_has_stopped_jobs(pgrp, proc))
    {
        pid_kill_pgrp(pgrp, SIGHUP, 0, NULL);
        pid_kill_pgrp(pgrp, SIGCONT, 0, NULL);
    }
}

static void exit_reparent_children(struct process *task, struct list_head *reap)
    REQUIRES(tasklist_lock)
{
    bool autoreap = false;
    bool group_dead = true;
    bool wake = false;
    bool notify;
    struct process *child, *next;
    struct process *leader;
    struct process *reaper = reaper_process(task);

    /* This function reparents children and notifies people that we're dying (process group,
     * parents, etc). Some care has to be had with regards to a few thread group edge cases, mostly
     * related to threads exiting after the main thread, etc. tasklist_lock write_lock protects task
     * lists, process groups, excludes against other tasks exiting. More details will follow. */
    kill_orphaned_pgrp(task);

    list_for_each_entry_safe (child, next, &task->children_head, sibbling_node)
    {
        list_remove(&child->sibbling_node);
        list_add_tail(&child->sibbling_node, &reaper->children_head);
        rcu_assign_pointer(child->parent, reaper);
        wake = true;
    }

    if (wake)
        wait_queue_wake_all(&reaper->sig->wait_child_event);

    /* Check if we should autoreap ourselves. This may happen for various reasons:
     * 1) We're a thread while not being a thread group leader (the parent will never wait for us)
     * 2) SIGCHLD has SA_NOCLDWAIT set
     */
    if (!thread_group_leader(task))
        autoreap = true;

    notify = false;
    leader = rcu_dereference_protected(task->sig->tg_leader, lockdep_tasklist_lock_held_write());

    /* If we are the leader, and last exiting; or the leader has exited and we're the last thread
     * exiting: We'll notify the group if need be; Mainly, the two big cases are:
     * 1) We're not set for autoreap yet
     * 2) We're not the thread group leader
     * If 1), parent_notify will take care of checking signal handlers for the corresponding (should
     * we reap) signal logic.
     * If 2), we're triggering this logic for the leader which passed away without anyone noticing.
     */
    if ((leader == task && task->sig->nr_threads == 1) ||
        (task_zombie(leader) && task->sig->nr_threads == 2))
    {
        /* Notify if our thread group leader is exiting/has exited and the thread group is now empty
         * (apart from the group leader and possibly us).
         */
        group_dead = true;
        notify = !autoreap || leader != task;
    }

    if (notify)
    {
        CHECK(group_dead);
        if (parent_notify(task->exit_code))
        {
            /* Ok. parent_notify told us we're autoreaping. Since it's a group exit, we want to
             * clear the whole thread_list out (should be either *us* or *us + leader*). */
            list_for_each_entry_safe (child, next, &task->sig->thread_list, thread_list_node.__lh)
            {
                list_remove(&child->sibbling_node);
                list_add(&child->sibbling_node, reap);
            }

            /* Make sure we don't hit the !thread_group_leader check below */
            return;
        }
    }

    /* If we're not the thread group leader, silently autoreap ourselves only */
    if (!thread_group_leader(task))
    {
        CHECK(autoreap);
        list_remove(&task->sibbling_node);
        list_add(&task->sibbling_node, reap);
    }
}

static void exit_do_ctid(void)
{
    if (current->ctid)
    {
        pid_t to_write = 0;
        copy_to_user(current->ctid, &to_write, sizeof(to_write));
        futex_wake((int *) current->ctid, INT_MAX);
    }
}

static void release_task(struct process *task) REQUIRES(tasklist_lock);

__attribute__((noreturn)) void do_exit(unsigned int exit_code)
{
    struct process *p, *next;

    DEFINE_LIST(reap);
    if (current->pid_ == 1)
    {
        pr_err("Panic: %s exited with exit code %u!\n", current->comm, exit_code);
        irq_enable();
        for (;;)
            sched_sleep_ms(10000);
    }

    current->exit_code = exit_code;
    current->flags |= PROCESS_EXITING;

    exit_do_ctid();
    exit_files(current);
    exit_fs(current);
    exit_mmap();

    /* vfork completion is done on execve _or_ task exit. So do it. There should be no memory
     * ordering problems due to the implicit memory barrier when starting threads. */
    if (current->vfork_compl)
    {
        vfork_compl_wake(current->vfork_compl);
        current->vfork_compl = NULL;
    }

    write_lock(&tasklist_lock);
    task_make_zombie(current);
    exit_reparent_children(current, &reap);

    for (struct proc_event_sub *s = current->sub_queue; s; s = s->next)
        s->valid_sub = false;

    /* Set this in this order exactly */
    get_current_thread()->flags = THREAD_IS_DYING;
    get_current_thread()->status = THREAD_DEAD;

    get_current_thread()->owner = NULL;
    list_for_each_entry_safe (p, next, &reap, sibbling_node)
        release_task(p);
    write_unlock(&tasklist_lock);

    sched_yield();

    while (true)
    {
        set_current_state(THREAD_DEAD);
        sched_yield();
    }
}

void sys_exit(int value)
{
    value &= 0xff;
    do_exit(make_wait4_wstatus(0, false, value));
    WARN_ON(1);
}

static void zap_others_thread_group(struct process *task)
{
    /* task->sighand->signal_lock held */
    struct process *t;

    for_each_thread (task, t)
    {
        if (t == task)
            continue;
        sigaddset(&t->sigqueue.pending, SIGKILL);
        signal_interrupt_task(t, SIGKILL);
    }
}

__attribute__((noreturn)) static void do_group_exit(int exit_code)
{
    /* First zap threads, then do our regular exit */
    struct signal_struct *sig = current->sig;
    struct sighand_struct *sighand = current->sighand;

    if (READ_ONCE(sig->signal_group_flags) & SIGNAL_GROUP_EXIT)
        exit_code = sig->signal_group_exit_code;
    else
    {
        /* Lock signals, check if we're the first in do_group_exit - if so, zap threads. then
         * continue */
        spin_lock(&sighand->signal_lock);
        if (sig->signal_group_flags & SIGNAL_GROUP_EXIT)
            exit_code = sig->signal_group_exit_code;
        else
        {
            sig->signal_group_exit_code = exit_code;
            sig->signal_group_flags = SIGNAL_GROUP_EXIT;
            zap_others_thread_group(current);
        }
        spin_unlock(&sighand->signal_lock);
    }

    do_exit(exit_code);
}

__attribute__((noreturn)) void process_exit_from_signal(int signum)
{
    do_group_exit(make_wait4_wstatus(signum, false, 0));
}

void sys_exit_group(int status)
{
    status &= 0xff;
    do_group_exit(make_wait4_wstatus(0, false, status));
}

static void process_remove_from_list(struct process *proc)
{
    list_remove_rcu(&proc->tasklist_node);
    /* Remove from the sibblings list */
    list_remove(&proc->sibbling_node);
}

void process_end(struct process *process)
{
    struct signal_struct *sig = process->sig;
    if (refcount_dec_and_test(&sig->refs))
        kfree(sig);

    thread_put(process->thr);
    process_dtor(process);
    kfree_rcu(process, rcu_head);
}

#define WAIT_INFO_MATCHING_ANY (1 << 0)
#define WAIT_INFO_MATCH_PGID   (1 << 1)

struct wait_info
{
    int wstatus;
    pid_t pid;
    struct rusage usage;
    int status;
    unsigned int flags;
    unsigned int options;
};

static void wait_info_init(struct wait_info *winfo, pid_t pid, unsigned int options)
{
    /* pid = -1: matches any process;
     * pid < 0: matches processes with pgid = -pid;
     * pid = 0: matches processes with pgid = process' pgid.
     * pid > 0: matches processes with pid = pid.
     */
    *winfo = (struct wait_info){};
    winfo->status = -ECHILD;
    winfo->pid = pid;
    if (pid == -1)
        winfo->flags |= WAIT_INFO_MATCHING_ANY;
    else if (pid < 0)
    {
        winfo->flags |= WAIT_INFO_MATCH_PGID;
        winfo->pid = -pid;
    }
    else if (pid == 0)
    {
        winfo->pid = pid_nr(task_pgrp(current));
        winfo->flags |= WAIT_INFO_MATCH_PGID;
    }

    /* WEXITED is always implied for wait4 */
    winfo->options = options | WEXITED;
}

static bool wait_should_reap(struct wait_info *w)
{
    return !(w->options & WNOWAIT);
}

static bool wait_matches_process(struct wait_info *info, struct process *proc)
{
    /* We're not waiting for !tg leaders */
    if (!thread_group_leader(proc))
        return false;
    if (info->flags & WAIT_INFO_MATCHING_ANY)
        return true;

    if (info->flags & WAIT_INFO_MATCH_PGID && pid_nr(task_pgrp(proc)) == info->pid)
        return true;

    if (info->pid == proc->pid_)
        return true;

    return false;
}

void task_ctime(struct process *task, hrtime_t *cutime, hrtime_t *cstime)
{
    *cutime = READ_ONCE(task->sig->cutime);
    *cstime = READ_ONCE(task->sig->cstime);
}

void tg_cputime(struct process *process, hrtime_t *utime, hrtime_t *stime)
{
    struct process *task;
    unsigned int seq;

    seq = 0;
retry:
    read_seqbegin_or_lock(&process->sig->stats_lock, &seq);
    *utime = READ_ONCE(process->sig->utime);
    *stime = READ_ONCE(process->sig->stime);
    rcu_read_lock();
    for_each_thread (process, task)
    {
        *utime += READ_ONCE(task->thr->cputime_info.user_time);
        *stime += READ_ONCE(task->thr->cputime_info.system_time);
    }
    rcu_read_unlock();
    if (read_seqretry(&process->sig->stats_lock, seq))
    {
        seq = 1;
        goto retry;
    }
    done_seqretry(&process->sig->stats_lock, seq);
}

void tg_cputime_clock_t(struct process *process, __clock_t *utime, __clock_t *stime)
{
    hrtime_t t0, t1;
    tg_cputime(process, &t0, &t1);
    *utime = t0 / NS_PER_MS;
    *stime = t1 / NS_PER_MS;
}

static int do_getrusage(int who, struct rusage *usage, struct process *proc)
{
    struct process *task;
    struct signal_struct *sig = proc->sig;
    hrtime_t utime = 0;
    hrtime_t stime = 0;
    unsigned int seq = 0;

retry:
    read_seqbegin_or_lock(&sig->stats_lock, &seq);
    memset(usage, 0, sizeof(struct rusage));
    utime = 0;
    stime = 0;
    switch (who)
    {
        case RUSAGE_BOTH:
        case RUSAGE_CHILDREN:
            task_ctime(proc, &utime, &stime);
            usage->ru_majflt = proc->sig->cmajflt;
            usage->ru_minflt = proc->sig->cminflt;
            usage->ru_nvcsw = proc->sig->cnvcsw;
            usage->ru_nivcsw = proc->sig->cnivcsw;
            if (who == RUSAGE_CHILDREN)
                break;

            /* fallthrough */
        case RUSAGE_SELF:
            utime += READ_ONCE(sig->utime);
            stime += READ_ONCE(sig->stime);
            usage->ru_majflt += READ_ONCE(sig->majflt);
            usage->ru_minflt += READ_ONCE(sig->minflt);
            usage->ru_nvcsw += sig->nvcsw;
            usage->ru_nivcsw += sig->nivcsw;
            rcu_read_lock();
            for_each_thread (proc, task)
            {
                utime += READ_ONCE(task->thr->cputime_info.user_time);
                stime += READ_ONCE(task->thr->cputime_info.system_time);
                usage->ru_majflt += task->majflt;
                usage->ru_minflt += task->minflt;
                usage->ru_nvcsw += task->nvcsw;
                usage->ru_nivcsw += task->nivcsw;
            }
            rcu_read_unlock();
            break;

        default:
            return -EINVAL;
    }

    if (read_seqretry(&sig->stats_lock, seq))
    {
        seq = 1;
        goto retry;
    }

    done_seqretry(&sig->stats_lock, seq);
    hrtime_to_timeval(utime, &usage->ru_utime);
    hrtime_to_timeval(stime, &usage->ru_stime);
    return 0;
}

int sys_getrusage(int who, struct rusage *user_usage)
{
    /* do_getrusage understands this flag but it isn't supposed to be exposed */
    if (who == RUSAGE_BOTH)
        return -EINVAL;

    struct rusage kusage;
    int st = 0;
    if ((st = do_getrusage(who, &kusage, current)) < 0)
        return st;

    return copy_to_user(user_usage, &kusage, sizeof(struct rusage));
}

static void process_accumulate_rusage(struct process *child, const struct rusage *usage)
{
    struct signal_struct *sig = current->sig;
    write_seqlock(&sig->stats_lock);
    sig->cstime += timeval_to_hrtime(&usage->ru_stime);
    sig->cutime += timeval_to_hrtime(&usage->ru_utime);
    sig->cmajflt += usage->ru_majflt;
    sig->cminflt += usage->ru_minflt;
    sig->cnivcsw += usage->ru_nivcsw;
    sig->cnvcsw += usage->ru_nvcsw;
    write_sequnlock(&sig->stats_lock);
}

static bool process_wait_exit(struct process *child, struct wait_info *winfo)
    REQUIRES(tasklist_lock)
{
    CHECK(!task_dead(child));

    if (!task_zombie(child))
        return false;

    spin_lock(&child->sighand->signal_lock);

    if (!task_zombie(child))
        goto no;

    if (!(winfo->options & WEXITED))
        goto no;

    if (thread_group_leader(child) && child->sig->nr_threads > 1)
    {
        /* Can't reap a thread group leader if there are still live threads */
        goto no;
    }

    WARN_ON(child->sig->nr_threads == 0);
    do_getrusage(RUSAGE_BOTH, &winfo->usage, child);

    winfo->pid = child->pid_;
    winfo->wstatus = child->exit_code;

    if (wait_should_reap(winfo))
    {
        process_accumulate_rusage(child, &winfo->usage);
        spin_unlock(&child->sighand->signal_lock);
        release_task(child);
    }
    else
        spin_unlock(&child->sighand->signal_lock);

    return true;
no:
    spin_unlock(&child->sighand->signal_lock);
    return false;
}

static bool process_wait_stop(struct process *child, struct wait_info *winfo)
    REQUIRES(tasklist_lock)
{
    struct signal_struct *sig = child->sig;
    if (!(sig->signal_group_flags & SIGNAL_GROUP_STOPPED))
        return false;

    spin_lock(&child->sighand->signal_lock);

    if (!(sig->signal_group_flags & SIGNAL_GROUP_STOPPED))
        goto no;

    if (sig->signal_group_flags & SIGNAL_GROUP_EXIT)
        goto no;

    if (!(winfo->options & WSTOPPED))
        goto no;

    /* We use exit_code = 0 to know it has been reaped */
    if (!sig->signal_group_exit_code)
        goto no;

    do_getrusage(RUSAGE_BOTH, &winfo->usage, child);
    winfo->pid = task_tgid(child);
    winfo->wstatus = sig->signal_group_exit_code;

    if (wait_should_reap(winfo))
        sig->signal_group_exit_code = 0;

    spin_unlock(&child->sighand->signal_lock);
    return true;
no:
    spin_unlock(&child->sighand->signal_lock);
    return false;
}

static bool process_wait_cont(struct process *child, struct wait_info *winfo)
    REQUIRES(tasklist_lock)
{
    if (!(child->sig->signal_group_flags & SIGNAL_GROUP_CONT))
        return false;

    spin_lock(&child->sighand->signal_lock);

    if (!(child->sig->signal_group_flags & SIGNAL_GROUP_CONT))
        goto no;

    if (child->sig->signal_group_flags & SIGNAL_GROUP_EXIT)
        goto no;

    if (!(winfo->options & WCONTINUED))
        goto no;

    do_getrusage(RUSAGE_BOTH, &winfo->usage, child);
    winfo->pid = task_tgid(child);
    winfo->wstatus = W_CONTINUED;
    if (wait_should_reap(winfo))
        child->sig->signal_group_flags &= ~SIGNAL_GROUP_CONT;

    spin_unlock(&child->sighand->signal_lock);
    return true;
no:
    spin_unlock(&child->sighand->signal_lock);
    return false;
}

#define WINFO_STATUS_OK     1
#define WINFO_STATUS_NOHANG 2

static bool wait_handle_processes(struct process *proc, struct wait_info *winfo)
    REQUIRES(tasklist_lock) NO_THREAD_SAFETY_ANALYSIS
{
    struct process *child, *next;
    list_for_each_entry_safe (child, next, &proc->children_head, sibbling_node)
    {
        if (!wait_matches_process(winfo, child))
            continue;

        winfo->status = 0;
        if (!process_wait_exit(child, winfo) && !process_wait_stop(child, winfo) &&
            !process_wait_cont(child, winfo))
            continue;

        winfo->status = WINFO_STATUS_OK;
        /* We'll want to stop iterating after waiting for a child */
        break;
    };

    return winfo->status == WINFO_STATUS_OK;
}

static bool wait_check_thread_group(struct process *proc, struct wait_info *winfo)
    REQUIRES(tasklist_lock)
{
    struct process *thread;

    winfo->status = -ECHILD;
    list_for_each_entry (thread, &proc->sig->thread_list, thread_list_node.__lh)
    {
        if (wait_handle_processes(thread, winfo))
            return true;
    }

    if (winfo->options & WNOHANG || winfo->status == -ECHILD)
    {
        if (winfo->options & WNOHANG)
            winfo->status = WINFO_STATUS_NOHANG;
        return true;
    }

    return false;
}

#define VALID_WAIT4_OPTIONS (WNOHANG | WUNTRACED | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT)

pid_t sys_wait4(pid_t pid, int *wstatus, int options, struct rusage *usage)
{
    if (options & ~VALID_WAIT4_OPTIONS)
        return -EINVAL;

    struct wait_info w;
    wait_info_init(&w, pid, options);
    /* TODO: We can probably loop without taking the write_lock necessarily. it is not needed for
     * paused processes for instance. */
    write_lock(&tasklist_lock);
    int st = wait_for_event_writelocked_interruptible(
        &current->sig->wait_child_event, wait_check_thread_group(current, &w), &tasklist_lock);
    write_unlock(&tasklist_lock);

    if (st < 0)
        return st;

    if (w.status != WINFO_STATUS_OK)
        return w.status == WINFO_STATUS_NOHANG ? 0 : w.status;

    if ((wstatus && copy_to_user(wstatus, &w.wstatus, sizeof(int)) < 0) ||
        (usage && copy_to_user(usage, &w.usage, sizeof(struct rusage)) < 0))
        return -EFAULT;
    return w.pid;
}

static void exit_signal(struct process *task)
{
    struct signal_struct *sig = task->sig;
    struct sighand_struct *sighand = task->sighand;
    struct tty *tty = NULL;

    /* Note: if we as the group leader are exiting, this means the whole thread group is going away.
     * wait4() (and autoreap) never reaps thread group leaders if it means there are still other
     * threads around.
     */
    bool group_leader = thread_group_leader(task);

    write_seqlock(&sig->stats_lock);
    sig->stime += task->thr->cputime_info.system_time;
    sig->utime += task->thr->cputime_info.user_time;
    sig->majflt += task->majflt;
    sig->minflt += task->minflt;
    sig->nvcsw += task->nvcsw;
    sig->nivcsw += task->nivcsw;
    write_sequnlock(&sig->stats_lock);

    spin_lock(&sighand->signal_lock);

    if (group_leader)
    {
        if (task_is_session_leader(task) && sig->ctty)
        {
            /* We'll clear out the tty later, without signal_lock */
            tty = sig->ctty;
            sig->ctty = NULL;
        }

        for (int i = 0; i < ITIMER_COUNT; i++)
            itimer_disarm(&sig->timers[i]);
    }

    /* Remove ourselves from every list we've been apart of. Sibblings, tasklist, pids, threads */
    pid_remove_pid(task->pid_struct, task);
    if (group_leader)
    {
        pid_remove_process(task_pgrp_locked(task), task, PIDTYPE_PGRP);
        pid_remove_process(task_session_locked(task), task, PIDTYPE_SID);
    }

    list_remove_rcu(&task->thread_list_node.__lh);
    process_remove_from_list(task);
    sig->nr_threads--;
    spin_unlock(&sighand->signal_lock);
    exit_sighand(task);

    if (tty)
        process_clear_tty(tty);

    if (group_leader)
        CHECK(sig->nr_threads == 0);
}

static void release_task(struct process *task) REQUIRES(tasklist_lock)
{
    /* Take care of reaping a task, including putting our reference. Putting the signal-related
     * structs happens here for now, but I'm afraid there could be races wrt signal sending...
     * XXX think this through. Maybe RCU is what we want...
     */
    CHECK(task_zombie(task));

    exit_signal(task);
    task_make_dead(task);

    process_put(task);
}

/**
 * @brief Zap the current process' threads and swap pids
 * current will become the new thread group leader.
 *
 * @return 0 on success, -EINTR if another exec is in progress
 */
int zap_threads_exec(void)
{
    struct signal_struct *sig = current->sig;
    struct sighand_struct *hand = current->sighand;

    /* Common case: We don't need to step into this logic */
    if (sig->nr_threads == 1)
        return 0;

    spin_lock(&hand->signal_lock);
    if (sig->signal_group_flags & SIGNAL_GROUP_EXIT)
    {
        /* uh oh, someone's waiting for us in another exec or exit. bye. */
        spin_unlock(&hand->signal_lock);
        return -EINTR;
    }

    /* We use SIGNAL_GROUP_EXIT to help us out over here, since we need to exclude exit anyways.
     * Other threads will act like they're exiting, but we are not. We'll clear this later. */
    sig->signal_group_flags |= SIGNAL_GROUP_EXIT;

    sig->group_notify_pending = sig->nr_threads - 1;
    zap_others_thread_group(current);
    while (sig->group_notify_pending)
    {
        /* TODO: KILLABLE... */
        set_current_state(THREAD_UNINTERRUPTIBLE);
        spin_unlock(&hand->signal_lock);
        sched_yield();
        spin_lock(&hand->signal_lock);
    }

    sig->signal_group_flags &= ~SIGNAL_GROUP_EXIT;
    spin_unlock(&hand->signal_lock);

    if (!thread_group_leader(current))
    {
        struct process *old_leader;
        /* Alright, switch tids and pids and tg leaders... make sure no one notices we're not the
         * leader. Add ourselves to process groups and sids. TODO: process times?
         */
        write_lock(&tasklist_lock);
        old_leader = rcu_dereference_protected(sig->tg_leader, lockdep_tasklist_lock_held_write());
        rcu_assign_pointer(sig->tg_leader, current);
        exchange_leader_pids(old_leader, current);
        /* Finally, whack the old leader */
        release_task(old_leader);
        write_unlock(&tasklist_lock);
    }

    return 0;
}
