/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define DEFINE_CURRENT
#include <errno.h>
#include <stdio.h>

#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/mm/slab.h>
#include <onyx/panic.h>
#include <onyx/pid.h>
#include <onyx/process.h>
#include <onyx/signal.h>
#include <onyx/task_switching.h>
#include <onyx/vm.h>
#include <onyx/wait_queue.h>

#include <uapi/signal.h>

static int send_signal_to_task(int signal, struct process *task, unsigned int flags,
                               siginfo_t *info, enum pid_type type);

/* Wide-enough type to contain all signals. In theory we have sigset_t, but this type is nicer to
 * work with */
typedef unsigned long sigmask_t;
#define SIGMASK(sig) (1UL << (sig - 1))

static inline bool siginmask(sigmask_t mask, int sig)
{
    DCHECK(sig < _NSIG);
    DCHECK(sig > 0);
    return mask & (1UL << (sig - 1));
}

static inline void sigdelmask(sigset_t *set, sigmask_t mask)
{
    set->__bits[0] &= ~mask;
}

static inline bool sigmaskinset(sigset_t *set, sigmask_t mask)
{
    return set->__bits[0] & mask;
}

static inline void sigandsetmask(sigset_t *set, sigmask_t mask)
{
    set->__bits[0] &= mask;
}

#define SIGNAL_STOP_MASK (SIGMASK(SIGSTOP) | SIGMASK(SIGTSTP) | SIGMASK(SIGTTIN) | SIGMASK(SIGTTOU))
#define SIGNAL_IGN_MASK                                                                           \
    (SIGMASK(SIGCHLD) | SIGMASK(SIGCONT) | SIGMASK(SIGURG) | SIGMASK(SIGWINCH) | SIGMASK(SIGIO) | \
     SIGMASK(SIGPWR))

#define SIG_KILL_MASK                                                                             \
    (SIGMASK(SIGHUP) | SIGMASK(SIGINT) | SIGMASK(SIGKILL) | SIGMASK(SIGUSR1) | SIGMASK(SIGUSR2) | \
     SIGMASK(SIGPIPE) | SIGMASK(SIGALRM) | SIGMASK(SIGTERM) | SIGMASK(SIGSTKFLT) |                \
     SIGMASK(SIGVTALRM) | SIGMASK(SIGPROF))

#define SIG_CORE_MASK                                                                             \
    (SIGMASK(SIGQUIT) | SIGMASK(SIGILL) | SIGMASK(SIGTRAP) | SIGMASK(SIGABRT) | SIGMASK(SIGBUS) | \
     SIGMASK(SIGFPE) | SIGMASK(SIGSEGV) | SIGMASK(SIGXCPU) | SIGMASK(SIGXFSZ) | SIGMASK(SIGSYS))

#define SIG_SYNCHRONOUS_MASK                                                                     \
    (SIGMASK(SIGILL) | SIGMASK(SIGTRAP) | SIGMASK(SIGBUS) | SIGMASK(SIGFPE) | SIGMASK(SIGSEGV) | \
     SIGMASK(SIGSYS))

#define sig_stop(sig)     siginmask(SIGNAL_STOP_MASK, sig)
#define sig_ignore(sig)   siginmask(SIGNAL_IGN_MASK, sig)
#define sig_kill(sig)     (siginmask(SIG_KILL_MASK, sig) || (sig) >= KERNEL_SIGRTMIN)
#define sig_coredump(sig) siginmask(SIG_CORE_MASK, sig)

#define SST_SIZE (_NSIG / 8 / sizeof(long))
void signotset(sigset_t *set)
{
    for (size_t i = 0; i < SST_SIZE; i++)
        set->__bits[i] = ~set->__bits[i];
}

bool signal_is_unblockable(int signum)
{
    switch (signum)
    {
        case SIGSTOP:
        case SIGKILL:
            return true;
    }

    return false;
}

static sigset_t task_pending_sigs(void)
{
    sigset_t ret;
    sigorset(&ret, &current->sigqueue.pending, &current->sig->shared_signals.pending);
    return ret;
}

static sigset_t task_eff_sigpending(void)
{
    sigset_t pending = task_pending_sigs();
    sigset_t mask = current->sigmask;
    signotset(&mask);
    sigandset(&pending, &pending, &mask);
    return pending;
}

static inline int sigffs(sigset_t *set)
{
    if (set->__bits[0] == 0)
        return -1;
    return __builtin_ffs(set->__bits[0]);
}

int signal_find(thread_t *unsed)
{
    sigset_t set = task_eff_sigpending();
    return sigffs(&set);
}

bool signal_is_empty(struct thread *thread)
{
    return signal_find(thread) == -1;
}

static void recalc_sigpending(void)
{
    /* Done with sighand->lock held */
    if (signal_is_empty(NULL))
        clear_task_flag(current, TF_SIGPENDING);
    else
        set_task_flag(current, TF_SIGPENDING);
}

#define SIGNAL_QUERY_POP          (1 << 0)
#define SIGNAL_PREFER_SYNCHRONOUS (1 << 1)

static struct sigpending *__signal_query_pending(int signum, unsigned int flags,
                                                 struct sigqueue *info)
{
    struct sigpending *pend;
    bool is_realtime_signal = signum >= KERNEL_SIGRTMIN;
    list_for_each_entry (pend, &info->pending_head, list_node)
    {
        if (pend->signum == signum)
        {
            /* Found one! */
            if (flags & SIGNAL_QUERY_POP)
            {
                list_remove(&pend->list_node);
                goto dequeue;
            }

            return pend;
        }
    }

    WARN_ON(1);
    return NULL;
dequeue:
    /* We'll clear it from the pending set if 1) it's realtime and there are no further signals or
     * 2) it's a standard signal (these don't queue) */

    if (!is_realtime_signal || !__signal_query_pending(signum, 0, info))
    {
        sigdelset(&info->pending, signum);
        recalc_sigpending();
    }

    return pend;
}

static struct sigpending *__signal_dequeue(unsigned int flags, struct sigqueue *queue)
{
    int sig;
    sigset_t pending = queue->pending;
    sigset_t mask = current->sigmask;
    signotset(&mask);
    sigandset(&pending, &pending, &mask);

    if (flags & SIGNAL_PREFER_SYNCHRONOUS)
    {
        /* Prefer a group of signals usually generated for synchronous exceptions (defined above) */
        if (sigmaskinset(&pending, SIG_SYNCHRONOUS_MASK))
            sigandsetmask(&pending, SIG_SYNCHRONOUS_MASK);
    }

    sig = sigffs(&pending);
    if (sig == -1)
    {
        /* No signal? Clear SIGPENDING. Various signal-related tasks set it sometimes, to get these
         * signal paths to run. It may not mean they had an actual signal pending. An easy example
         * is a group exit or a group stop. */
        clear_task_flag(current, TF_SIGPENDING);
        return NULL;
    }

    return __signal_query_pending(sig, flags, queue);
}

static struct sigpending *signal_dequeue(unsigned int flags)
{
    struct sigpending *pend;
    CHECK(spin_lock_held(&current->sighand->signal_lock));
    /* Try to handle thread signals first, then process-wide ones */
    pend = __signal_dequeue(flags, &current->sigqueue);
    if (!pend)
        pend = __signal_dequeue(flags, &current->sig->shared_signals);
    return pend;
}

void force_sigsegv(int sig)
{
    int flags = 0;
    siginfo_t info = {};
    if (sig == SIGSEGV)
        flags |= SIGNAL_FORCE;

    info.si_code = SI_KERNEL;
    info.si_signo = SIGSEGV;

    read_lock(&tasklist_lock);
    send_signal_to_task(sig, current, flags, &info, PIDTYPE_PID);
    read_unlock(&tasklist_lock);
}

void signal_end_delivery(struct arch_siginfo *sinfo)
{
    /* Set the proper signal mask as the last (arch-independent) step in signal delivery */
    sigset_t new_blocked = current->sigmask;
    sigset_t sigm;
    memcpy(&sigm, &sinfo->action.sa_mask, sizeof(sigm));
    sigorset(&new_blocked, &new_blocked, &sigm);

    if (!(sinfo->action.sa_flags & SA_NODEFER))
    {
        /* POSIX specifies that the signal needs to be blocked while being handled */
        sigaddset(&new_blocked, sinfo->signum);
    }

    signal_setmask(&new_blocked);
}

static void do_signal_stop(int signo)
{
    /* current->sighand->signal_lock held */
    /* Ok. We're starting (or continuing?) a signal stop. Check which one it is */
    struct signal_struct *sig = current->sig;
    struct process *t;
    if (!test_task_flag(current, TF_STOP_PENDING))
    {
        CHECK(signo != 0);
        /* Start the group stop. We'll decrement ourselves later on */
        sig->nr_group_stop_pending = sig->nr_threads;
        sig->signal_group_exit_code = W_STOPPED_SIG(signo);
        for_each_thread (current, t)
        {
            if (t == current)
                continue;
            /* Set STOP_PENDING + SIGPENDING (so signal_is_pending does the right thing) */
            set_task_flag(current, TF_STOP_PENDING | TF_SIGPENDING);
            signal_interrupt_task(t, signo);
        }
    }

    if (--sig->nr_group_stop_pending == 0)
    {
        sig->signal_group_flags |= SIGNAL_GROUP_STOPPED;
        /* Ok, group stop finished (either we're a single thread, or the last thread in the group
         * stop). Notify the parent */
        read_lock(&tasklist_lock);
        notify_process_stop_cont(current, sig->signal_group_exit_code);
        read_unlock(&tasklist_lock);
    }
    /* Set THREAD_STOPPED, unlock signal_lock and yield. There's no risk of a race because signal
     * delivery will take the signal lock, and we set the status before unlocking. */
    set_current_state(THREAD_STOPPED);
    clear_task_flag(current, TF_STOP_PENDING);
    spin_unlock(&current->sighand->signal_lock);
    sched_yield();
    spin_lock(&current->sighand->signal_lock);
}

static void do_sigcont_notify(void)
{
    struct signal_struct *sig = current->sig;
    /* XXX Lock ordering is screwed up here (and in do_signal_stop). signal_lock nests under
     * tasklist_lock, not vice-versa. Can we do this exclusively under RCU? */
    read_lock(&tasklist_lock);
    notify_process_stop_cont(current, W_CONTINUED);
    read_unlock(&tasklist_lock);
    sig->signal_group_exit_code = W_CONTINUED;
    sig->signal_group_flags &= ~(SIGNAL_GROUP_CONT_PENDING | SIGNAL_GROUP_STOPPED);
    sig->signal_group_flags |= SIGNAL_GROUP_CONT;
}

static void free_sigpending(struct sigpending *pend)
{
    kfree(pend->info);
    kfree(pend);
}

bool find_signal(struct arch_siginfo *sinfo)
{
    struct sigpending *pending;
    struct k_sigaction *ksa;
    int sig;
    spin_lock(&current->sighand->signal_lock);

    /* This infinite loop should speed things up by letting us handle things
     * like getting SIGSTOP'd and then handling the SIGCONT in the same interruption/kernel exit.
     */
    while (true)
    {
        /* If sigkill is pending, we're either getting killed or part of a group exit. As such,
         * do a group exit */
        if (current->sig->signal_group_flags & SIGNAL_GROUP_CONT_PENDING)
        {
            /* SIGCONT notification pending, handle it */
            do_sigcont_notify();
            continue;
        }

        if (sigismember(&current->sigqueue.pending, SIGKILL))
        {
            spin_unlock(&current->sighand->signal_lock);
            process_exit_from_signal(SIGKILL);
        }

        if (test_task_flag(current, TF_STOP_PENDING))
        {
            do_signal_stop(0);
            continue;
        }

        pending = signal_dequeue(SIGNAL_QUERY_POP | SIGNAL_PREFER_SYNCHRONOUS);
        if (!pending)
        {
            spin_unlock(&current->sighand->signal_lock);
            break;
        }

        ksa = &current->sighand->sigtable[pending->signum];

        /* Handle basic signal dispositions. */
        if (ksa->sa_handler == SIG_IGN)
        {
            free_sigpending(pending);
            continue;
        }
        if (ksa->sa_handler != SIG_DFL)
        {
            /* arch-specific code will want to handle this signal disposition, save information and
             * break. */
            sinfo->action = *ksa;
            sinfo->signum = pending->signum;
            if (ksa->sa_flags & SA_RESETHAND)
            {
                /* If so, we need to reset the handler to SIG_DFL and clear SA_SIGINFO */
                ksa->sa_handler = SIG_DFL;
                ksa->sa_flags &= ~SA_SIGINFO;
            }

            memcpy(&sinfo->info, pending->info, sizeof(siginfo_t));
            free_sigpending(pending);
            spin_unlock(&current->sighand->signal_lock);
            return true;
        }

        /* Default signal dispositions... We can already discard siginfo at least */
        sig = pending->signum;
        free_sigpending(pending);
        if (sig_stop(sig))
        {
            do_signal_stop(sig);
            /* pending freed, sighand locked. loop again */
            continue;
        }
        else if (sig_ignore(sig))
            continue;
        else if (sig_kill(sig) || sig_coredump(sig))
        {
            spin_unlock(&current->sighand->signal_lock);
            process_exit_from_signal(sig);
            UNREACHABLE();
        }

        WARN_ON(1);
        UNREACHABLE();
    }

    return false;
}

int kernel_raise_signal(int sig, struct process *process, unsigned int flags, siginfo_t *info)
{
    /* kernel_raise_signal sends to the *tgid* not the pid */
    int err;
    read_lock(&tasklist_lock);
    err = send_signal_to_task(sig, process, 0, info, PIDTYPE_TGID);
    read_unlock(&tasklist_lock);
    return err;
}

static void do_signal_force_unblock(int signal, struct process *task)
{
    /* Do it like Linux, and restore the handler to SIG_DFL,
     * and unmask the thread
     */
    struct k_sigaction *ksa = &task->sighand->sigtable[signal];

    ksa->sa_handler = SIG_DFL;
    ksa->sa_flags |= SA_IMMUTABLE;
    sigdelset(&task->sigmask, signal);
}

int may_kill(int signum, struct process *target, siginfo_t *info)
{
    bool is_kernel = !info || info->si_code > 0;
    int st = 0;

    if (is_kernel)
        return 0;

    struct creds *c = creds_get();
    struct creds *other = NULL;
    if (c->euid == 0)
        goto out;

    other = __creds_get(target);
    if (c->euid == other->ruid || c->euid == other->suid || c->ruid == other->ruid ||
        c->ruid == other->suid)
        st = 0;
    else
        st = -1;

out:
    if (other)
        creds_put(other);
    creds_put(c);
    return st;
}

static bool is_default_ignored(int signal)
{
    return sig_ignore(signal);
}

static bool is_signal_ignored(struct process *process, int signal)
{
    return process->sighand->sigtable[signal].sa_handler == SIG_IGN ||
           (process->sighand->sigtable[signal].sa_handler == SIG_DFL && is_default_ignored(signal));
}

bool signal_may_wake(int signum)
{
    return signum == SIGCONT || signum == SIGKILL;
}

static void __signal_drop_sigs(sigmask_t sigs, struct sigqueue *queue)
{
    struct sigpending *pend, *next;
    /* Fast path: no signal is pending, whack nothing, walk nothing */
    if (!sigmaskinset(&queue->pending, sigs))
        return;

    list_for_each_entry_safe (pend, next, &queue->pending_head, list_node)
    {
        if (siginmask(sigs, pend->signum))
        {
            list_remove(&pend->list_node);
            free_sigpending(pend);
        }
    }

    sigdelmask(&queue->pending, sigs);
}

static void signal_drop_sigs(sigmask_t sigs, struct process *task)
{
    struct process *t;
    /* Drop the shared (process-directed) signals, then walk through all threads and wack them there
     * too */
    __signal_drop_sigs(sigs, &task->sig->shared_signals);
    for_each_thread (task, t)
        __signal_drop_sigs(sigs, &task->sigqueue);
}

/**
 * @brief Do special signal behavior (at send time)
 * POSIX specifiers a couple of behaviors for SIGCONT and stop signals, such as the unqueueing of
 * other signals. Do it here.
 *
 * @param signal Signal we're sending
 * @param task Task we're sending to
 */
void signal_do_special_behaviour(int signal, struct process *task)
{
    struct process *t;
    if (signal == SIGCONT)
    {
        /* Drop all stop signals and setup things for the SIGCONT */
        signal_drop_sigs(SIGNAL_STOP_MASK, task);
        task->sig->signal_group_flags &= ~SIGNAL_GROUP_STOPPED;
        task->sig->signal_group_flags |= SIGNAL_GROUP_CONT_PENDING;
        for_each_thread (task, t)
            signal_interrupt_task(task, SIGCONT);
    }
    else if (sig_stop(signal))
    {
        /* Drop SIGCONT signals */
        signal_drop_sigs(SIGMASK(SIGCONT), task);
    }
}

void signal_interrupt_task(struct process *task, int signal)
{
    struct thread *thr = task->thr;
    set_task_flag(task, TF_SIGPENDING);
    /* XXX: This smp_mb _does not work_. This is broken af and doesn't really order it with
     * anything other than the wakeup. We need to take care of it inside the scheduler. */
    smp_mb();

    /* We're only waking the thread up for two reasons: It's either in an interruptible sleep
     * OR it's stopped and we're SIGCONT'ing it */
    if (thr->status == THREAD_INTERRUPTIBLE ||
        (thr->status == THREAD_STOPPED && signal_may_wake(signal)))
        thread_wake_up(thr);
}

static void signal_set_pending(struct process *task, int signal, enum pid_type type)
{
    struct process *t;
    if (type == PIDTYPE_PID)
    {
        /* Really simple case. Wake up *this* task. But only if the signal is not blocked. If it is,
         * since this is thread-directed we have no other chance. */
        if (sigismember(&task->sigmask, signal))
            return;
        t = task;
        goto set_pending;
    }

    for_each_thread (task, t)
    {
        /* Try to find a thread which does not have this signal blocked */
        if (!sigismember(&t->sigmask, signal))
            goto set_pending;
    }

    /* Could not find an okay thread. Return. sigprocmask will re-wakeup if required. */
    return;
set_pending:
    signal_interrupt_task(t, signal);
}

static int __send_signal_to_task(int signal, struct process *task, unsigned int flags,
                                 siginfo_t *info, enum pid_type type)
{
    /* task->sighand->signal_lock held */
    struct sigpending *pending;
    siginfo_t *copy_siginfo = NULL;
    struct sigqueue *queue;

    signal_do_special_behaviour(signal, task);
    queue = type == PIDTYPE_TGID ? &task->sig->shared_signals : &task->sigqueue;

    /* Don't bother to set it as pending if sig == SIG_IGN or it's set to the default
     * and the default is to ignore. Note: We don't skip it if sig == SIG_IGN *and* it's masked.
     */
    bool is_signal_ign = is_signal_ignored(task, signal) && !(signal_is_unblockable(signal));
    bool is_masked = sigismember(&task->sigmask, signal);

    bool signal_delivery_blocked = (is_signal_ign || is_masked) && type == PIDTYPE_PID;

    if (flags & SIGNAL_FORCE && signal_delivery_blocked)
    {
        /* If the signal delivery is being forced for some reason
         * (usually, it's because of a hardware exception), we'll need
         * to unblock it forcefully.
         */
        do_signal_force_unblock(signal, task);
    }
    else if (is_signal_ign && !is_masked)
        return 0;

    bool standard_signal = signal < KERNEL_SIGRTMIN;
    if (standard_signal && sigismember(&queue->pending, signal))
    {
        /* Already signaled, return success */
        return 0;
    }

    pending = kmalloc(sizeof(*pending), GFP_ATOMIC);
    if (!pending)
        goto failure_oom;

    copy_siginfo = kmalloc(sizeof(*copy_siginfo), GFP_ATOMIC);
    if (!copy_siginfo)
    {
        kfree(pending);
        goto failure_oom;
    }

    if (info)
        memcpy(copy_siginfo, info, sizeof(siginfo_t));
    else
    {
        memset(copy_siginfo, 0, sizeof(siginfo_t));
        copy_siginfo->si_code = SI_KERNEL;
    }

    copy_siginfo->si_signo = signal;

    pending->info = copy_siginfo;
    pending->signum = signal;

    list_add(&pending->list_node, &queue->pending_head);

    /* If the signal was not pending, add it to pending and try to wake someone up (if need be) */
    if (!sigismember(&queue->pending, signal))
    {
        sigaddset(&queue->pending, signal);
        signal_set_pending(task, signal, type);
    }

    return 0;
failure_oom:

    if (flags & SIGNAL_FORCE)
    {
        /* I don't think there's another way to do this, for now */
        /* Our kernel's OOM behavior and mechanisms are iffy *at best* */
        panic("SIGNAL_FORCE couldn't be done");
    }

    return -ENOMEM;
}

static int send_signal_to_task(int signal, struct process *task, unsigned int flags,
                               siginfo_t *info, enum pid_type type)
{
    int err;
    spin_lock(&task->sighand->signal_lock);
    err = __send_signal_to_task(signal, task, flags, info, type);
    spin_unlock(&task->sighand->signal_lock);
    return err;
}

bool is_valid_signal(int sig)
{
    return sig > 0 && sig < NSIG;
}

bool pid_is_system_process(pid_t pid)
{
    return pid == 1;
}

static int signal_send_all(int signal, int flags, siginfo_t *info)
{
    int signals_sent = 0;
    struct process *task;

    read_lock(&tasklist_lock);
    list_for_each_entry_rcu (task, &tasklist, tasklist_node)
    {
        /* Skip threads */
        if (!thread_group_leader(task))
            continue;
        /* Do not allow signalling pid 1 and ourselves. */
        if (pid_is_system_process(task_tgid(task)) || same_thread_group(task, current))
            continue;

        if (may_kill(signal, task, info) < 0)
            continue;

        if (kernel_raise_signal(signal, task, 0, info) == 0)
            signals_sent++;
    }
    read_unlock(&tasklist_lock);

    return signals_sent != 0 ? 0 : -EPERM;
}

int signal_kill_pg(int sig, int flags, siginfo_t *info, pid_t pid)
{
    bool own = pid == 0;
    int err = -ESRCH;
    struct pid *pidp;

    read_lock(&tasklist_lock);
    pidp = own ? task_pgrp(current) : pid_lookup(-pid);
    if (pidp)
        err = pid_kill_pgrp(pidp, sig, flags, info);
    read_unlock(&tasklist_lock);
    return err;
}

int sys_kill(pid_t pid, int sig)
{
    int st = 0;
    struct process *p = NULL;
    struct creds *c = NULL;
    siginfo_t info = {};

    if (pid > 0)
    {
        p = get_process_from_pid(pid);
        if (!p)
            return -ESRCH;
    }

    if (sig == 0)
    {
        goto out;
    }

    if (!is_valid_signal(sig))
    {
        st = -EINVAL;
        goto out;
    }

    c = creds_get();

    info.si_signo = sig;
    info.si_code = SI_USER;
    info.si_uid = c->euid;
    info.si_pid = task_tgid(current);

    creds_put(c);

    if (pid <= 0)
    {
        if (pid == -1)
            st = signal_send_all(sig, 0, &info);
        else if (pid < -1 || pid == 0)
            st = signal_kill_pg(sig, 0, &info, pid);
    }
    else
    {
        if (may_kill(sig, p, &info) < 0)
            goto out;

        st = kernel_raise_signal(sig, p, 0, &info);
    }
out:
    if (p)
        process_put(p);
    return st;
}

int sys_sigaction(int signum, const struct k_sigaction *act, struct k_sigaction *oldact)
{
    int st = 0;
    if (!is_valid_signal(signum))
        return -EINVAL;

    /* If both pointers are NULL, just return 0 (We can't do anything) */
    if (!oldact && !act)
        return 0;

    struct k_sigaction old;
    struct k_sigaction news;

    if (act)
    {
        if (copy_from_user(&news, act, sizeof(struct k_sigaction)) < 0)
            return -EFAULT;

        if (news.sa_handler == SIG_ERR)
            return -EINVAL;

        /* Check if it's actually possible to set a handler to this signal */
        switch (signum)
        {
            /* If not, return EINVAL */
            case SIGKILL:
            case SIGSTOP:
                return -EINVAL;
        }
    }

    /* Lock the signal table */
    spin_lock(&current->sighand->signal_lock);

    /* If old_act, save the old action */
    if (oldact)
        memcpy(&old, &current->sighand->sigtable[signum], sizeof(struct k_sigaction));

    if (act)
    {
        /* Don't let anyone set a signal handler that was marked immutable */
        if (old.sa_flags & SA_IMMUTABLE)
        {
            st = -EINVAL;
            goto skip;
        }

        /* If act, set the new action */
        memcpy(&current->sighand->sigtable[signum], &news, sizeof(news));

        if (is_signal_ignored(current, signum))
        {
            /* POSIX specifies that we should drop all pending signals if setting a disposition
             * (thru SIG_IGN or SIG_DFL with default ignored) to ignore. */
            sigmask_t mask = SIGMASK(signum);
            signal_drop_sigs(mask, current);
        }
    }

skip:
    spin_unlock(&current->sighand->signal_lock);

    if (oldact && copy_to_user(oldact, &old, sizeof(struct k_sigaction)) < 0)
        return -EFAULT;

    return st;
}

static void sanitize_sigmask(sigset_t *set)
{
    sigdelset(set, SIGKILL);
    sigdelset(set, SIGSTOP);
}

static void sigmask_updated(sigset_t *oldmask)
{
    /* Update the current TF_SIGPENDING flag, and try to retarget and possibly wakeup for shared
     * signals that are not longer handleable by us */
    /* Unhandleable = shared & ~(oldmask - sigmask) = shared & ~(oldmask & ~sigmask) */
    struct process *t;
    sigset_t set = current->sig->shared_signals.pending;
    sigset_t mask = current->sigmask;
    signotset(&mask);
    sigandset(&mask, oldmask, &mask);
    signotset(&mask);
    sigandset(&set, &set, &mask);

    /* Try to find threads that can deal with the shared-pending-but-not-handleable set. This may
     * result in waking up too many threads, but it is unavoidable and required for correctness. */
    for_each_thread (current, t)
    {
        if (sigisemptyset(&set))
            break;
        /* Can we take off some signals and hand it off to this task? */
        mask = t->sigmask;
        signotset(&mask);
        sigandset(&mask, &mask, &set);
        if (sigisemptyset(&mask))
            continue;

        /* ??? */
        if (t == current)
            break;
        /* Clear off those bits from set */
        signotset(&mask);
        sigandset(&set, &set, &mask);
        /* Do a signal wake up + TF_SIGPENDING set, Signal can be safely set as 0 as SIGSTOP,
         * SIGCONT and SIGKILL are never maskeable */
        signal_interrupt_task(t, 0);
    }

    recalc_sigpending();
}

int sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigset_size)
{
    if (sigset_size != sizeof(sigset_t))
        return -EINVAL;

    sigset_t koldset = current->sigmask;

    if (set)
    {
        sigset_t kset;
        if (copy_from_user(&kset, set, sizeof(sigset_t)) < 0)
            return -EFAULT;
        sanitize_sigmask(&kset);

        spin_lock(&current->sighand->signal_lock);
        switch (how)
        {
            case SIG_BLOCK: {
                sigorset(&current->sigmask, &current->sigmask, &kset);
                break;
            }
            case SIG_UNBLOCK: {
                signotset(&kset);
                sigandset(&current->sigmask, &current->sigmask, &kset);
                break;
            }
            case SIG_SETMASK: {
                current->sigmask = kset;
                break;
            }
            default:
                spin_unlock(&current->sighand->signal_lock);
                return -EINVAL;
        }

        /* Update pending and retarget current pending signals. */
        sigmask_updated(&koldset);
        spin_unlock(&current->sighand->signal_lock);
    }

    if (oldset)
    {
        if (copy_to_user(oldset, &koldset, sizeof(sigset_t)) < 0)
            return -EFAULT;
    }
    return 0;
}

bool signal_is_pending(void)
{
    struct thread *t = get_current_thread();
    if (!t || !t->owner)
        return false;
    return test_task_flag(t->owner, TF_SIGPENDING);
}

int sys_sigsuspend(const sigset_t *uset)
{
    sigset_t set;
    if (copy_from_user(&set, uset, sizeof(set)))
        return -EFAULT;

    signal_setmask_and_save(&set);
    while (!signal_is_pending())
    {
        /* TODO: This is racy and we need some special care in the scheduler for certain signal
         * cases, I think... But we already needed it anyway. */
        set_current_state(THREAD_INTERRUPTIBLE);
        sched_yield();
    }

    return -ERESTARTNOHAND;
}

int sys_pause(void)
{
    struct wait_queue wq;
    init_wait_queue_head(&wq);

    wait_for_event_interruptible(&wq, false);

    return -ERESTARTNOHAND;
}

#define TGKILL_CHECK_PID (1 << 0)
#define TGKILL_SIGQUEUE  (1 << 1)

int do_tgkill(int pid, int tid, int sig, unsigned int flags, siginfo_t *kinfo)
{
    int st = 0;
    struct process *p;
    siginfo_t info = {};

    if (tid < 0)
        return -EINVAL;

    /* TODO: RCU-ify */
    read_lock(&tasklist_lock);
    st = -ESRCH;
    p = get_process_from_pid_noref(tid);
    if (!p)
        goto out;

    if (flags & TGKILL_CHECK_PID && task_tgid(p) != pid)
    {
        st = -ESRCH;
        goto out;
    }

    if (!is_valid_signal(sig))
    {
        st = -EINVAL;
        goto out;
    }

    if (!(flags & TGKILL_SIGQUEUE))
    {
        struct creds *c = creds_get();

        info.si_signo = sig;
        info.si_code = SI_TKILL;
        info.si_uid = c->euid;
        info.si_pid = task_tgid(current);

        creds_put(c);
    }
    else
    {
        memcpy(&info, kinfo, sizeof(info));
    }

    st = -EPERM;
    if (may_kill(sig, p, &info) < 0)
        goto out;

    st = send_signal_to_task(sig, p, 0, &info, PIDTYPE_PID);
out:
    read_unlock(&tasklist_lock);
    return st;
}

int sys_tkill(int tid, int sig)
{
    return do_tgkill(-1, tid, sig, 0, NULL);
}

int sys_tgkill(int pid, int tid, int sig)
{
    return do_tgkill(pid, tid, sig, TGKILL_CHECK_PID, NULL);
}

int sanitize_rt_sigqueueinfo(siginfo_t *info, pid_t pid)
{
    if (task_tgid(current) == pid)
        return 0;

    if (info->si_code >= 0)
        return -1;
    if (info->si_code == SI_TKILL)
        return -1;

    return 0;
}

int sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo)
{
    int st = 0;
    siginfo_t info;
    if (copy_from_user(&info, uinfo, sizeof(info)) < 0)
        return -EFAULT;

    if (sanitize_rt_sigqueueinfo(&info, pid) < 0)
        return -EPERM;

    struct process *p = get_process_from_pid(pid);
    if (!p)
        return -ESRCH;

    if (sig == 0)
    {
        goto out;
    }

    if (!is_valid_signal(sig))
    {
        st = -EINVAL;
        goto out;
    }

    st = kernel_raise_signal(sig, p, 0, &info);

out:
    process_put(p);
    return st;
}

int sys_rt_tgsigqueueinfo(pid_t pid, pid_t tid, int sig, siginfo_t *uinfo)
{
    siginfo_t info;
    if (copy_from_user(&info, uinfo, sizeof(info)) < 0)
        return -EFAULT;

    if (sanitize_rt_sigqueueinfo(&info, pid) < 0)
        return -EPERM;

    return do_tgkill(pid, tid, sig, TGKILL_CHECK_PID | TGKILL_SIGQUEUE, &info);
}

void signal_do_execve(struct process *proc)
{
    /* Clear the non-ignored signal disposition */
    for (int i = 0; i < NSIG; i++)
    {
        struct k_sigaction *sa = &proc->sighand->sigtable[i];
        if (sa->sa_handler != SIG_IGN)
            sa->sa_handler = NULL;

        sa->sa_flags = 0;
        memset(&sa->sa_mask, 0, sizeof(sa->sa_mask));
        sa->sa_restorer = NULL;
    }

    /* Clear the altstack */
    sigaltstack_init(&proc->altstack);
}

#define CURRENT_SIGSETLEN 8

/* We need to separate this function since you can't have 2 wait_for_events */
/* TODO: Maybe fix it? */
long sigtimedwait_forever(struct wait_queue *wq)
{
    return wait_for_event_interruptible(wq, false);
}

int sys_rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *utimeout,
                        size_t sigsetlen)
{
    struct sigpending *pending = NULL;
    int st = 0;
    struct wait_queue wq;
    struct timespec timeout = {};

    if (sigsetlen != CURRENT_SIGSETLEN)
        return -EINVAL;
    init_wait_queue_head(&wq);

    if (utimeout && copy_from_user(&timeout, utimeout, sizeof(timeout)) < 0)
        return -EFAULT;

    if (!timespec_valid(&timeout, false))
        return -EINVAL;

    sigset_t kset;

    if (copy_from_user(&kset, set, sizeof(kset)) < 0)
        return -EFAULT;

        /* TODO: The implementation is not quite correct */
#if 0
	sigset_t old;
	/* Save the old blocked set */
	memcpy(&old, &thread->sinfo.sigmask, sizeof(sigset_t));
	
	/* Silently ignore all attempts to wait for SIGKILL and SIGSTOP */
	sigdelset(&kset, SIGKILL);
	sigdelset(&kset, SIGSTOP);

	/* We invert the sigset in order to know what we need to block, and then
	 * we AND it with the old blocked set so we know what we're actually blocking.
	 */
	signotset(&kset);

	{

	scoped_lock g{thread->sinfo.lock};
	sigandset(&thread->sinfo.sigmask, &old, &kset);
	thread->sinfo.__update_pending();

	}
#endif

    hrtime_t timeout_ns = timespec_to_hrtime(&timeout);

    long res;
    if (utimeout)
        res = wait_for_event_timeout_interruptible(&wq, false, timeout_ns);
    else
    {
        res = sigtimedwait_forever(&wq);
    }

    if (res == -ETIMEDOUT)
        return -EAGAIN;

    spin_lock(&current->sighand->signal_lock);
    /* As in the normal signal handling path, pop the sigpending */
    pending = signal_dequeue(SIGNAL_QUERY_POP);
    spin_unlock(&current->sighand->signal_lock);
    if (WARN_ON(!pending))
    {
        /* Weird? Think about this */
        return st;
    }

    st = pending->signum;

    if (copy_to_user(info, pending->info, sizeof(siginfo_t)) < 0)
        st = -EFAULT;

    kfree(pending->info);
    kfree(pending);
    return st;
}

int sys_rt_sigpending(sigset_t *uset, size_t sigsetlen)
{
    if (sigsetlen != CURRENT_SIGSETLEN)
        return -EINVAL;

    spin_lock(&current->sighand->signal_lock);
    sigset_t set = task_pending_sigs();
    spin_unlock(&current->sighand->signal_lock);

    if (copy_to_user(uset, &set, sizeof(set)) < 0)
        return -EFAULT;

    return 0;
}

bool executing_in_altstack(const struct syscall_frame *frm, const stack_t *stack)
{
    /* TODO: This is arch-dependent and we'd probably be better off wrapping this access
     * with a arch-dependent macro.
     */
    /* TODO: This depends on whether the stack grows downwards or upwards. This logic covers the
     * first case. */
#ifdef __x86_64__
    unsigned long sp = frm->rsp;
#elif defined(__riscv)
    unsigned long sp = frm->regs.sp;
#elif defined(__aarch64__)
    unsigned long sp = frm->regs.sp;
#endif
    unsigned long alt_sp = (unsigned long) stack->ss_sp;
    unsigned long alt_stack_limit = alt_sp + stack->ss_size;
    return sp >= alt_sp && sp < alt_stack_limit;
}

static int alt_stack_sp_flags(const struct syscall_frame *frame, const stack_t *stack)
{
    return executing_in_altstack(frame, stack) ? SS_ONSTACK : 0;
}

#define VALID_SIGALTSTACK_FLAGS (SS_AUTODISARM | SS_DISABLE)

int sys_sigaltstack(const stack_t *new_stack, stack_t *old_stack, const struct syscall_frame *frame)
{
    stack_t *stack = &current->altstack;

    if (old_stack)
    {
        stack_t kold = {};
        kold.ss_sp = stack->ss_sp;
        kold.ss_size = stack->ss_size;
        kold.ss_flags = alt_stack_sp_flags(frame, stack) | stack->ss_flags;

        if (copy_to_user(old_stack, &kold, sizeof(kold)) < 0)
            return -EFAULT;
    }

    if (new_stack)
    {
        stack_t stk;
        if (copy_from_user(&stk, new_stack, sizeof(stk)) < 0)
            return -EFAULT;

        if (stk.ss_flags & ~VALID_SIGALTSTACK_FLAGS)
            return -EINVAL;

        if (executing_in_altstack(frame, stack))
            return -EPERM;

        if (stk.ss_flags & SS_DISABLE)
        {
            /* We're disabling, zero out size and sp, and set the flag properly. */
            stack->ss_flags = SS_DISABLE;
            stack->ss_size = 0;
            stack->ss_sp = NULL;
        }
        else
        {
            if (stk.ss_size < MINSIGSTKSZ)
                return -ENOMEM;

            stack->ss_sp = stk.ss_sp;
            stack->ss_size = stk.ss_size;
            stack->ss_flags = stk.ss_flags;
        }
    }

    return 0;
}

int raise_sig_thr(int sig, struct process *task, unsigned int flags, siginfo_t *info)
{
    /* We might not need tasklist lock in case we hold a ref or is current... */
    int err;
    read_lock(&tasklist_lock);
    err = send_signal_to_task(sig, task, flags, info, PIDTYPE_PID);
    read_unlock(&tasklist_lock);
    return err;
}

int raise_sig_curthr(int sig, unsigned int flags, siginfo_t *info)
{
    return raise_sig_thr(sig, current, flags, info);
}

void signal_setmask(const sigset_t *mask)
{
    spin_lock(&current->sighand->signal_lock);
    sigset_t newmask = *mask;
    sanitize_sigmask(&newmask);
    current->sigmask = newmask;
    recalc_sigpending();
    spin_unlock(&current->sighand->signal_lock);
}

/**
 * @brief Set the mask and store the old one for saving later
 * To be used by syscalls that need such semantics (ppoll, pselect, sigsuspend, etc)
 *
 * @param mask New sigmask
 */
void signal_setmask_and_save(const sigset_t *mask)
{
    current->original_sigset = current->sigmask;
    signal_setmask(mask);
    set_task_flag(current, TF_RESTORE_SIGMASK);
}

/**
 * @brief Restore the saved sigmask
 * To be used by syscalls that need such semantics (ppoll, pselect, sigsuspend, etc)
 *
 */
void signal_restore_sigmask(void)
{
    signal_setmask(&current->original_sigset);
    clear_task_flag(current, TF_RESTORE_SIGMASK);
}

/**
 * @brief Notify this task's parent that we're exiting
 * We have to be careful and check if we need to, e.g, autoreap. write_lock needs to be held when
 * calling.
 *
 * @param exit_code Exit code to notify with
 * @retval true If task should be autoreaped (thus no signal was sent, nor did we wake anyone up)
 */
bool parent_notify(unsigned int exit_code)
{
    bool autoreap = false;
    struct process *parent =
        rcu_dereference_protected(current->parent, lockdep_tasklist_lock_held_write());
    struct sighand_struct *sighand = parent->sighand;
    struct k_sigaction *act;
    int sig = SIGCHLD;

    siginfo_t info = {};

    info.si_signo = sig;
    info.si_pid = pid_nr(current->sig->tgid);
    info.si_uid = current->cred.ruid;
    info.si_stime = current->system_time / NS_PER_MS;
    info.si_utime = current->user_time / NS_PER_MS;

    if (WIFEXITED(exit_code))
    {
        info.si_code = CLD_EXITED;
        info.si_status = WEXITSTATUS(exit_code);
    }
    else if (WIFSIGNALED(exit_code))
    {
        info.si_code = CLD_KILLED;
        info.si_status = WTERMSIG(exit_code);
    }

    /* Take the parent's signal_lock. We're going to atomically check if need to send a signal or
     * wake it up, or if we should autoreap, etc */
    spin_lock(&sighand->signal_lock);
    act = &sighand->sigtable[sig];

    if (act->sa_handler == SIG_IGN || act->sa_flags & SA_NOCLDWAIT)
    {
        /* SIGCHLD's handler is SIG_IGN? Or SA_NOCLDWAIT? Then we autoreap, as per POSIX */
        autoreap = true;
        /* If SIG_IGN, don't even bother entering the signal sending logic. Whether NOCLDWAIT gets a
         * signal is implementation defined, but we go the linux route. */
        if (act->sa_handler == SIG_IGN)
            sig = 0;
    }

    /* If !IGN (DFL or specific handler) */
    if (sig > 0)
        __send_signal_to_task(sig, parent, 0, &info, PIDTYPE_TGID);
    /* Note: Even when autreap, we need to wake up processes in wait4 just so any processes that run
     * out of children don't get stuck and get a nice -ECHILD. */
    wait_queue_wake_all(&parent->sig->wait_child_event);
    spin_unlock(&sighand->signal_lock);
    return autoreap;
}

/**
 * @brief Notify this task's parent that we're stopping/continuing
 * We have to be careful and check if we need to, e.g, not send anything. tasklist read_lock needs
 * to be held when calling.
 *
 * @param exit_code Stop code to notify with
 * @retval true If task was woken up
 */
bool notify_process_stop_cont(struct process *task, unsigned int exit_code)
{
    struct process *parent = rcu_dereference_protected(task->parent, lockdep_tasklist_lock_held());
    struct sighand_struct *sighand = parent->sighand;
    struct k_sigaction *act;
    int sig = SIGCHLD;

    siginfo_t info = {};

    info.si_signo = sig;
    info.si_pid = pid_nr(task->sig->tgid);
    info.si_uid = task->cred.ruid;
    info.si_stime = task->system_time / NS_PER_MS;
    info.si_utime = task->user_time / NS_PER_MS;

    if (WIFEXITED(exit_code))
    {
        info.si_code = CLD_EXITED;
        info.si_status = WEXITSTATUS(exit_code);
    }
    else if (WIFSIGNALED(exit_code))
    {
        info.si_code = CLD_KILLED;
        info.si_status = WTERMSIG(exit_code);
    }

    /* Take the parent's signal_lock. We're going to atomically check if need to send a signal or
     * wake it up, etc */
    spin_lock(&sighand->signal_lock);
    act = &sighand->sigtable[sig];

    if (act->sa_handler == SIG_IGN || act->sa_flags & SA_NOCLDSTOP)
    {
        /* If SIG_IGN or SA_NOCLDSTOP, don't send a signal */
        sig = 0;
    }

    /* If !IGN (DFL or specific handler) */
    if (sig > 0)
        __send_signal_to_task(sig, parent, 0, &info, PIDTYPE_TGID);
    /* Note: We must wake up wait4 calls. */
    wait_queue_wake_all(&parent->sig->wait_child_event);
    spin_unlock(&sighand->signal_lock);
    return sig > 0;
}
