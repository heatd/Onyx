/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdio.h>

#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/panic.h>
#include <onyx/pid.h>
#include <onyx/process.h>
#include <onyx/signal.h>
#include <onyx/task_switching.h>
#include <onyx/vm.h>
#include <onyx/wait_queue.h>

#include <uapi/signal.h>

#include <onyx/memory.hpp>

void signal_default_term(int signum)
{
    process_exit_from_signal(signum);
}

void signal_default_core(int signum)
{
    /* TODO: Generate a core dump */
    signal_default_term(signum);
}

void signal_default_ignore(int signum)
{
    (void) signum;
}

atomic<unsigned int> stopped = 0;

void signal_do_stop(int signum)
{
    struct process *current = get_current_process();
    auto current_thread = get_current_thread();

    if (!(current_thread->sinfo.flags & THREAD_SIGNAL_STOPPING))
    {
        /* For every thread in the process, tell it to stop */
        process_for_every_thread(current, [&](thread *t) -> bool {
            if (t == current_thread)
                return true;

            scoped_lock g{t->sinfo.lock};
            t->sinfo.flags |= THREAD_SIGNAL_STOPPING;
            t->sinfo.signal_pending = true;

            if (t->status == THREAD_INTERRUPTIBLE)
                thread_wake_up(t);

            return true;
        });

        current_thread->sinfo.flags |= THREAD_SIGNAL_STOPPING;

        current->signal_group_flags |= SIGNAL_GROUP_STOPPED;
        current->signal_group_flags &= ~SIGNAL_GROUP_CONT;

        /* TODO: The last thread to stop should do this, not the first. */

        notify_process_stop_cont(current, signum);
    }

    set_current_state(THREAD_STOPPED);

    stopped++;

    sched_yield();
    stopped--;
}

/* This table only handles non-realtime signals (so, from signo 1 to 31, inclusive) */
sighandler_t dfl_signal_handlers[] = {signal_default_term,
                                      /*[SIGHUP] = */ signal_default_term,
                                      /*[SIGINT] = */ signal_default_term,
                                      /*[SIGQUIT] = */ signal_default_core,
                                      /*[SIGILL] = */ signal_default_core,
                                      /*[SIGTRAP] = */ signal_default_core,
                                      /*[SIGABRT] =*/signal_default_core,
                                      /*[SIGBUS] =*/signal_default_core,
                                      /*[SIGFPE] =*/signal_default_core,
                                      /*[SIGKILL] =*/signal_default_term,
                                      /*[SIGUSR1] =*/signal_default_term,
                                      /*[SIGSEGV] =*/signal_default_core,
                                      /*[SIGUSR2] =*/signal_default_term,
                                      /*[SIGPIPE] =*/signal_default_term,
                                      /*[SIGALRM] =*/signal_default_term,
                                      /*[SIGTERM] =*/signal_default_term,
                                      /*[SIGSTKFLT] =*/signal_default_term,
                                      /*[SIGCHLD] =*/signal_default_ignore,
                                      /*[SIGCONT] =*/signal_default_ignore,
                                      /*[SIGSTOP] =*/signal_do_stop,
                                      /*[SIGTSTP] =*/signal_do_stop,
                                      /*[SIGTTIN] =*/signal_do_stop,
                                      /*[SIGTTOU] =*/signal_do_stop,
                                      /*[SIGURG] =*/signal_default_ignore,
                                      /*[SIGXCPU] =*/signal_default_core,
                                      /*[SIGXFSZ] =*/signal_default_core,
                                      /*[SIGVTALRM] =*/signal_default_term,
                                      /*[SIGPROF] =*/signal_default_term,
                                      /*[SIGWINCH] =*/signal_default_ignore,
                                      /*[SIGIO] =*/signal_default_ignore,
                                      /*[SIGPWR] =*/signal_default_ignore,
                                      /*[SIGSYS] =*/signal_default_core};

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

void do_default_signal(int signum, struct sigpending *pend)
{

    /* For realtime signals (which we don't include in the dfl_signal_handlers), the default action
     * is to terminate the process.
     */
    bool is_term = signal_is_realtime(signum) ||
                   dfl_signal_handlers[signum] == signal_default_term ||
                   dfl_signal_handlers[signum] == signal_default_core;

    if (!is_term) [[likely]]
    {
        dfl_signal_handlers[signum](signum);
        return;
    }

    dfl_signal_handlers[signum](signum);

    __builtin_unreachable();
}

int signal_find(struct thread *thread)
{
    sigset_t *set = &thread->sinfo.pending_set;
    sigset_t *blocked_set = &thread->sinfo.sigmask;

    for (int i = 1; i < NSIG; i++)
    {
        if (sigismember(set, i) && !sigismember(blocked_set, i))
        {
            assert(i != 0);
            return i;
        }
    }

    return -1;
}

bool signal_is_empty(struct thread *thread)
{
    sigset_t *set = &thread->sinfo.pending_set;
    sigset_t *blocked_set = &thread->sinfo.sigmask;
    for (int i = 1; i < NSIG; i++)
    {
        if (sigismember(set, i) && !sigismember(blocked_set, i))
            return false;
    }

    return true;
}

#define SIGNAL_QUERY_POP (1 << 0)

struct sigpending *signal_query_pending(int signum, unsigned int flags, struct signal_info *info)
{
    list_for_every (&info->pending_head)
    {
        struct sigpending *pend = container_of(l, struct sigpending, list_node);

        if (pend->signum == signum)
        {
            /* Found one! */
            if (flags & SIGNAL_QUERY_POP)
                list_remove(&pend->list_node);
            return pend;
        }
    }

    return NULL;
}

bool deliver_signal(int signum, struct sigpending *pending, struct registers *regs);

/* Returns negative if deliver_signal shouldn't execute the rest of the code, and should return
 * immediately */
int force_sigsegv(struct sigpending *pending, struct registers *regs)
{
    int signum = pending->signum;

    pending->info->si_code = SI_KERNEL;
    pending->info->si_signo = SIGSEGV;
    pending->info->si_addr = NULL;

    /* If we were trying to deliver SEGV; just do the default signal */
    if (signum == SIGSEGV)
    {
        do_default_signal(signum, pending);
    }
    else
    {
        /* Else, try to deliver a SIGSEGV */
        deliver_signal(SIGSEGV, pending, regs);
        /* Explicitly return here in order not to execute the rest of the code */
        return -1;
    }

    return 0;
}

void signal_unqueue(int signum, struct thread *thread)
{
    bool is_realtime_signal = signum >= KERNEL_SIGRTMIN;
    bool should_delete = true;

    if (is_realtime_signal)
    {
        /* Search the query'ed backlog to see if there are other
         * realtime signals(of the same signum, of course) queued.
         */

        should_delete = signal_query_pending(signum, 0, &thread->sinfo) == NULL;
    }

    if (should_delete)
    {
        sigdelset(&thread->sinfo.pending_set, signum);
    }

    thread->sinfo.__update_pending();
}

bool signal_uncatcheable(int signum)
{
    return signal_is_stopping(signum) || signum == SIGKILL;
}

bool deliver_signal(int signum, struct sigpending *pending, struct registers *regs)
{
    struct thread *thread = get_current_thread();
    struct process *process = thread->owner;

    struct k_sigaction *k_sigaction = &process->sigtable[signum];
    void (*handler)(int) = k_sigaction->sa_handler;
    bool defer_user = false;

    /* TODO: Handle SA_RESTART */
    /* TODO: Handle SA_NOCLDWAIT */
    /* TODO: Handle SA_NOCLDSTOP */

    if (handler != SIG_DFL && !signal_uncatcheable(signum))
    {
        defer_user = true;
        if (signal_setup_context(pending, k_sigaction, regs) < 0)
        {
            if (force_sigsegv(pending, regs) < 0)
                return true;
        }
    }
    else
    {
        do_default_signal(signum, pending);
    }

    if (k_sigaction->sa_flags & SA_RESETHAND)
    {
        /* If so, we need to reset the handler to SIG_DFL and clear SA_SIGINFO */
        k_sigaction->sa_handler = SIG_DFL;
        k_sigaction->sa_flags &= ~SA_SIGINFO;
    }

    sigset_t new_blocked;
    memcpy(&new_blocked, &k_sigaction->sa_mask, sizeof(new_blocked));

    if (!(k_sigaction->sa_flags & SA_NODEFER))
    {
        /* POSIX specifies that the signal needs to be blocked while being handled */
        sigaddset(&new_blocked, signum);
    }

    // Re-lock it
    scoped_lock g{thread->sinfo.lock};

    thread->sinfo.__add_blocked(&new_blocked);

    signal_unqueue(signum, thread);

    return defer_user;
}

unsigned long sched_get_preempt_counter(void);

void handle_signal(struct registers *regs)
{
    /* We can't do signals while in kernel space */
    if (in_kernel_space_regs(regs))
    {
        return;
    }

    context_tracking_enter_kernel();

    if (irq_is_disabled())
        irq_enable();

    struct thread *thread = get_current_thread();

    thread->sinfo.times_interrupted++;

    struct process *process = thread->owner;

    scoped_lock g{process->signal_lock};

    scoped_lock g2{thread->sinfo.lock};

    /* This infinite loop should speed things up by letting us handle things
     * like getting SIGSTOP'd and then handling the SIGCONT in the same interruption/kernel exit.
     */
    while (true)
    {
        if (thread->sinfo.flags & THREAD_SIGNAL_EXITING)
        {
            g2.unlock();
            g.unlock();
            thread_exit();
        }

        if (thread->sinfo.flags & THREAD_SIGNAL_STOPPING)
        {
            g2.unlock();
            g.unlock();
            signal_do_stop(0);
            g.lock();
            g2.lock();
            continue;
        }

        /* Find an available signal */
        int signum = signal_find(thread);

        /* Oh no, no more signals :(( */
        if (signum < 0)
            break;

        auto pending = signal_query_pending(signum, SIGNAL_QUERY_POP, &thread->sinfo);

        assert(pending != NULL);

        // We need to unlock and relock the process and thread signal locks due to
        // copy_to/from_user, which may sleep
        g2.unlock();
        g.unlock();

        bool defer = deliver_signal(signum, pending, regs);

        g.lock();
        g2.lock();

        if (defer)
            break;
    }

    context_tracking_exit_kernel();
}

int kernel_raise_signal(int sig, struct process *process, unsigned int flags, siginfo_t *info)
{
    struct thread *t = nullptr;

    spin_lock(&process->thread_list_lock);

    list_for_every (&process->thread_list)
    {
        struct thread *thr = container_of(l, struct thread, thread_list_head);

        if (!sigismember(&thr->sinfo.sigmask, sig))
        {
            t = thr;
            break;
        }
    }

    if (t == nullptr)
    {
        if (list_is_empty(&process->thread_list))
        {
            // Process is a zombie, return success (doesn't matter if the signal is not delivered,
            // no one is expecting it.)
            spin_unlock(&process->thread_list_lock);
            return 0;
        }

        /* If the signal is masked everywhere, just pick the first thread... */
        t = container_of(list_first_element(&process->thread_list), struct thread,
                         thread_list_head);
    }

    assert(t != nullptr);

    thread_get(t);

    spin_unlock(&process->thread_list_lock);

    int st = kernel_tkill(sig, t, flags, info);

    thread_put(t);

    return st;
}

void do_signal_force_unblock(int signal, struct thread *thread)
{
    /* Do it like Linux, and restore the handler to SIG_DFL,
     * and unmask the thread
     */

    struct process *process = thread->owner;

    process->sigtable[signal].sa_handler = SIG_DFL;
    sigdelset(&thread->sinfo.sigmask, signal);
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
    return dfl_signal_handlers[signal] == signal_default_ignore;
}

static bool is_signal_ignored(struct process *process, int signal)
{
    return process->sigtable[signal].sa_handler == SIG_IGN ||
           (process->sigtable[signal].sa_handler == SIG_DFL && is_default_ignored(signal));
}

bool signal_may_wake(int signum)
{
    return signum == SIGCONT || signum == SIGKILL;
}

atomic<unsigned int> woke = 0;

void signal_do_special_behaviour(int signal, struct thread *thread)
{
    auto proc = thread->owner;

    if (signal == SIGCONT)
    {
        /* If any stop signals are pending, unqueue them */
        signal_unqueue(SIGSTOP, thread);
        signal_unqueue(SIGTSTP, thread);
        signal_unqueue(SIGTTIN, thread);
        signal_unqueue(SIGTTOU, thread);

        process_for_every_thread(proc, [&](struct thread *t) -> bool {
            bool should_lock = thread != t;

            /* The locks should make this immune to races */
            if (should_lock)
                spin_lock(&t->sinfo.lock);

            if (t->sinfo.flags & THREAD_SIGNAL_STOPPING)
            {
                thread_wake_up(t);
                woke++;
            }

            t->sinfo.flags &= ~THREAD_SIGNAL_STOPPING;

            t->sinfo.__update_pending();

            if (should_lock)
                spin_unlock(&t->sinfo.lock);

            return true;
        });

        bool was_stopped = proc->signal_group_flags & SIGNAL_GROUP_STOPPED;

        proc->signal_group_flags &= ~SIGNAL_GROUP_STOPPED;

        if (was_stopped)
        {
            proc->signal_group_flags |= SIGNAL_GROUP_CONT;
            notify_process_stop_cont(proc, SIGCONT);
        }
    }
    else if (signal_is_stopping(signal) && proc->sigtable[signal].sa_handler == SIG_DFL)
    {
        signal_unqueue(SIGCONT, thread);
    }
    else if (signal == SIGKILL)
    {
        signal_unqueue(SIGSTOP, thread);
        signal_unqueue(SIGTSTP, thread);
        signal_unqueue(SIGTTIN, thread);
        signal_unqueue(SIGTTOU, thread);

        process_for_every_thread(proc, [&](struct thread *t) -> bool {
            bool should_lock = thread != t;

            /* The locks should make this immune to races */
            if (should_lock)
                spin_lock(&t->sinfo.lock);

            if (t->sinfo.flags & THREAD_SIGNAL_STOPPING)
            {
                thread_wake_up(t);
                woke++;
            }

            t->sinfo.flags &= ~THREAD_SIGNAL_STOPPING;
            t->sinfo.__update_pending();

            if (should_lock)
                spin_unlock(&t->sinfo.lock);

            return true;
        });
    }
}

int kernel_tkill(int signal, struct thread *thread, unsigned int flags, siginfo_t *info)
{
    struct process *process = thread->owner;
    unique_ptr<struct sigpending> pending;
    siginfo_t *copy_siginfo = nullptr;

    if (may_kill(signal, process, info) < 0)
        return -EPERM;

    scoped_lock g{process->signal_lock};
    scoped_lock g2{thread->sinfo.lock};

    signal_do_special_behaviour(signal, thread);

    /* Don't bother to set it as pending if sig == SIG_IGN or it's set to the default
     * and the default is to ignore.
     */
    bool is_signal_ign = is_signal_ignored(process, signal) && !(signal_is_unblockable(signal));

    bool is_masked = sigismember(&thread->sinfo.sigmask, signal);

    bool signal_delivery_blocked = is_signal_ign || is_masked;

    if (flags & SIGNAL_FORCE && signal_delivery_blocked)
    {
        /* If the signal delivery is being forced for some reason
         * (usually, it's because of a hardware exception), we'll need
         * to unblock it forcefully.
         */
        do_signal_force_unblock(signal, thread);
    }
    else if (is_signal_ign)
    {
        return 0;
    }

    bool standard_signal = signal < KERNEL_SIGRTMIN;

    if (standard_signal && sigismember(&thread->sinfo.pending_set, signal))
    {
        /* Already signaled, return success */
        goto success;
    }

    pending = make_unique<struct sigpending>();
    if (!pending)
    {
        goto failure_oom;
    }

    copy_siginfo = new siginfo_t;
    if (!copy_siginfo)
    {
        goto failure_oom;
    }

    if (info)
    {
        memcpy(copy_siginfo, info, sizeof(siginfo_t));
    }
    else
    {
        memset(copy_siginfo, 0, sizeof(siginfo_t));
        copy_siginfo->si_code = SI_KERNEL;
    }

    copy_siginfo->si_signo = signal;

    pending->info = copy_siginfo;
    pending->signum = signal;

    list_add(&pending->list_node, &thread->sinfo.pending_head);

    pending.release();

    sigaddset(&thread->sinfo.pending_set, signal);

    if (!sigismember(&thread->sinfo.sigmask, signal))
    {
        thread->sinfo.signal_pending = true;
        /* We're only waking the thread up for two reasons: It's either in an interruptible sleep
         * OR it's stopped and we're SIGCONT'ing it */
        if (thread->status == THREAD_INTERRUPTIBLE ||
            (thread->status == THREAD_STOPPED && signal_may_wake(signal)))
            thread_wake_up(thread);
    }

success:
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

bool signal_is_masked(struct thread *thread, int sig)
{
    sigset_t *set = &thread->sinfo.sigmask;
    return (bool) sigismember(set, sig);
}

bool is_valid_signal(int sig)
{
    return sig > 0 && sig < NSIG;
}

struct send_all_info
{
    int signals_sent;
    siginfo_t *info;
    int signum;

    constexpr send_all_info(siginfo_t *i, int sig) : signals_sent{}, info{i}, signum{sig}
    {
    }
};

bool pid_is_system_process(pid_t pid)
{
    return pid == 1;
}

int signal_send_all(int signal, int flags, siginfo_t *info)
{
    send_all_info i{info, signal};

    for_every_process(
        [](process *p, void *ctx) -> bool {
            /* Do not allow signalling pid 1 and ourselves. */
            if (pid_is_system_process(p->get_pid()) || p == get_current_process())
                return true;

            send_all_info *c = (send_all_info *) ctx;

            if (may_kill(c->signum, p, c->info) < 0)
                return true;

            if (kernel_raise_signal(c->signum, p, 0, c->info) < 0)
                return true;

            c->signals_sent++;
            return true;
        },
        &i);

    return i.signals_sent != 0 ? 0 : -EPERM;
}

pid::auto_pid process_get_pgrp(process *p)
{
    scoped_lock g{p->pgrp_lock};

    auto pg = p->process_group;

    pg->ref();

    return pg;
}

int signal_kill_pg(int sig, int flags, siginfo_t *info, pid_t pid)
{
    bool own = pid == 0;

    pid::auto_pid pgrp_res = own ? process_get_pgrp(get_current_process()) : pid::lookup(-pid);

    if (!pgrp_res)
        return -ESRCH;

    return pgrp_res->kill_pgrp(sig, flags, info);
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
    info.si_pid = get_current_process()->get_pid();

    creds_put(c);

    if (pid <= 0)
    {
        if (pid == -1)
        {
            st = signal_send_all(sig, 0, &info);
        }
        else if (pid < -1 || pid == 0)
        {
            st = signal_kill_pg(sig, 0, &info, pid);
        }
    }
    else
        st = kernel_raise_signal(sig, p, 0, &info);

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

    struct process *proc = get_current_process();

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

    {
        /* Lock the signal table */
        scoped_lock g{proc->signal_lock};

        /* If old_act, save the old action */
        if (oldact)
        {
            memcpy(&old, &proc->sigtable[signum], sizeof(struct k_sigaction));
        }

        if (act)
        {
            /* If act, set the new action */
            memcpy(&proc->sigtable[signum], &news, sizeof(news));
        }
    }

    if (oldact && copy_to_user(oldact, &old, sizeof(struct k_sigaction)) < 0)
        return -EFAULT;

    return st;
}

int sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigset_size)
{
    if (sigset_size != sizeof(sigset_t))
        return -EINVAL;

    struct thread *current = get_current_thread();
    sigset_t koldset = current->sinfo.get_mask();

#if 0
	if(set) printk("sigprocmask %d %lx\n", how, set->__bits[0]);
#endif

    if (set)
    {
        sigset_t kset;
        if (copy_from_user(&kset, set, sizeof(sigset_t)) < 0)
            return -EFAULT;

        switch (how)
        {
            case SIG_BLOCK: {
                current->sinfo.add_blocked(&kset);
                break;
            }
            case SIG_UNBLOCK: {
                current->sinfo.unblock(kset);
                break;
            }
            case SIG_SETMASK: {
                current->sinfo.set_blocked(&kset);
                break;
            }
            default:
                return -EINVAL;
        }
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
    if (!t)
        return false;
#if 0
	if(t->sinfo.signal_pending == true)
		printk("Signal pending!\n");
#endif

    return t->sinfo.signal_pending;
}

int sys_sigsuspend(const sigset_t *uset)
{
    struct thread *current = get_current_thread();

    sigset_t set;
    if (copy_from_user(&set, uset, sizeof(sigset_t)) < 0)
        return -EFAULT;

    /* First, save the old sigset */
    memcpy(&current->sinfo.original_sigset, &current->sinfo.sigmask, sizeof(sigset_t));
    current->sinfo.flags |= THREAD_SIGNAL_ORIGINAL_SIGSET;
    /* Now, set the signal mask */
    current->sinfo.set_blocked(&set);

    /* Now, wait for a signal */
    struct wait_queue wq;
    init_wait_queue_head(&wq);

    wait_for_event_interruptible(&wq, false);

    return -EINTR;
}

int sys_pause()
{
    struct wait_queue wq;
    init_wait_queue_head(&wq);

    wait_for_event_interruptible(&wq, false);

    return -EINTR;
}

#define TGKILL_CHECK_PID (1 << 0)
#define TGKILL_SIGQUEUE  (1 << 1)

int do_tgkill(int pid, int tid, int sig, unsigned int flags, siginfo_t *kinfo)
{
    int st = 0;
    siginfo_t info = {};

    if (tid < 0)
        return -EINVAL;

    struct thread *t = thread_get_from_tid(tid);
    if (!t)
    {
        return -ESRCH;
    }

    /* Can't send signals to kernel threads */
    if (t->flags & THREAD_KERNEL)
    {
        st = -EINVAL;
        goto out;
    }

    if (flags & TGKILL_CHECK_PID && t->owner->get_pid() != pid)
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
        info.si_pid = get_current_process()->get_pid();

        creds_put(c);
    }
    else
    {
        memcpy(&info, kinfo, sizeof(info));
    }

    st = kernel_tkill(sig, t, 0, &info);

out:
    thread_put(t);

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
    struct process *current = get_current_process();

    if (current->get_pid() == pid)
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
        struct k_sigaction *sa = &proc->sigtable[i];
        if (sa->sa_handler != SIG_IGN)
            sa->sa_handler = NULL;

        sa->sa_flags = 0;
        memset(&sa->sa_mask, 0, sizeof(sa->sa_mask));
        sa->sa_restorer = NULL;
    }

    /* Clear the altstack */
    struct thread *t = get_current_thread();

    memset(&t->sinfo.altstack, 0, sizeof(t->sinfo.altstack));
    t->sinfo.altstack.ss_flags = SS_DISABLE;
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
    if (sigsetlen != CURRENT_SIGSETLEN)
        return -EINVAL;

    struct sigpending *pending = NULL;
    int st = 0;
    struct process *process = get_current_process();
    struct thread *thread = get_current_thread();

    struct wait_queue wq;
    init_wait_queue_head(&wq);

    struct timespec timeout = {};

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

    spin_lock(&process->signal_lock);
    spin_lock(&thread->sinfo.lock);

    /* Find a pending signal */
    int signum = signal_find(thread);
    assert(signum > 0);

    /* If it's not a member of set, error out with EINTR(it will be handled on syscall return). */
    if (!sigismember(&kset, signum))
    {
        st = -EINTR;
        goto out;
    }

    /* As in the normal signal handling path, pop the sigpending */
    pending = signal_query_pending(signum, SIGNAL_QUERY_POP, &thread->sinfo);

    assert(pending != NULL);

    signal_unqueue(signum, thread);

    st = pending->signum;

    if (copy_to_user(info, pending->info, sizeof(siginfo_t)) < 0)
    {
        st = -EFAULT;
    }

    delete pending;

out:
    spin_unlock(&thread->sinfo.lock);
    spin_unlock(&process->signal_lock);

    return st;
}

int sys_rt_sigpending(sigset_t *uset, size_t sigsetlen)
{
    struct thread *current = get_current_thread();

    if (sigsetlen != CURRENT_SIGSETLEN)
        return -EINVAL;

    auto set = current->sinfo.get_pending_set();

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
    unsigned long sp = frm->user_sp;
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
    struct thread *current = get_current_thread();
    struct signal_info *sinfo = &current->sinfo;

    if (old_stack)
    {
        stack_t kold = {};
        kold.ss_sp = sinfo->altstack.ss_sp;
        kold.ss_size = sinfo->altstack.ss_size;
        kold.ss_flags = alt_stack_sp_flags(frame, &sinfo->altstack) | sinfo->altstack.ss_flags;

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

        if (executing_in_altstack(frame, &sinfo->altstack))
            return -EPERM;

        stack_t *s = &sinfo->altstack;

        if (stk.ss_flags & SS_DISABLE)
        {
            /* We're disabling, zero out size and sp, and set the flag properly. */
            s->ss_flags = SS_DISABLE;
            s->ss_size = 0;
            s->ss_sp = NULL;
        }
        else
        {
            if (stk.ss_size < MINSIGSTKSZ)
                return -ENOMEM;

            s->ss_sp = stk.ss_sp;
            s->ss_size = stk.ss_size;
            s->ss_flags = stk.ss_flags;
        }
    }

    return 0;
}

void signal_info::reroute_signals(process *p)
{
    scoped_lock g{lock};

    list_for_every_safe (&pending_head)
    {
        auto pending = container_of(l, struct sigpending, list_node);

        list_remove(&pending->list_node);

        if (!p->route_signal(pending))
        {
            delete pending;
        }
    }
}

signal_info::~signal_info()
{
    scoped_lock g{lock};

    list_for_every_safe (&pending_head)
    {
        auto pending = container_of(l, struct sigpending, list_node);

        list_remove(&pending->list_node);
        delete pending;
    }
}
