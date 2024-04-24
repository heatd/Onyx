/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_SIGNAL_H
#define _ONYX_SIGNAL_H

#include <stdbool.h>

#include <onyx/list.h>
#include <onyx/spinlock.h>

#include <uapi/signal.h>

#ifdef __cplusplus
#include <onyx/scoped_lock.h>
#endif

__BEGIN_CDECLS

#define KERNEL_SIGRTMIN 32
#define KERNEL_SIGRTMAX 64

static inline int sigemptyset(sigset_t *set)
{
    for (size_t i = 0; i < _SIGSET_SIZE; i++)
        set->__bits[i] = 0;
    return 0;
}

static inline int sigaddset(sigset_t *set, int sig)
{
    unsigned s = sig - 1;
    set->__bits[s / _NSIG_PER_WORD] |= (1UL << (s % _NSIG_PER_WORD));
    return 0;
}

static inline int sigdelset(sigset_t *set, int sig)
{
    unsigned s = sig - 1;
    set->__bits[s / _NSIG_PER_WORD] &= ~(1UL << (s % _NSIG_PER_WORD));
    return 0;
}

static inline int sigismember(const sigset_t *set, int sig)
{
    unsigned s = sig - 1;
    return set->__bits[s / _NSIG_PER_WORD] & (1UL << (s % _NSIG_PER_WORD));
}

static inline int sigisemptyset(const sigset_t *set)
{
    for (size_t i = 0; i < _SIGSET_SIZE; i++)
    {
        if (set->__bits[i])
            return 0;
    }

    return 1;
}

static inline int sigorset(sigset_t *dest, const sigset_t *left, const sigset_t *right)
{
    unsigned long i = 0, *d = (unsigned long *) dest, *l = (unsigned long *) left,
                  *r = (unsigned long *) right;
    for (; i < _SIGSET_SIZE; i++)
        d[i] = l[i] | r[i];
    return 0;
}

static inline int sigandset(sigset_t *dest, const sigset_t *left, const sigset_t *right)
{
    unsigned long i = 0, *d = (unsigned long *) dest, *l = (unsigned long *) left,
                  *r = (unsigned long *) right;
    for (; i < _SIGSET_SIZE; i++)
        d[i] = l[i] & r[i];
    return 0;
}
void signotset(sigset_t *set);

struct sigpending
{
    siginfo_t *info;
    int signum;
    struct list_head list_node;

#ifdef __cplusplus
    constexpr sigpending() : info{nullptr}, signum{}, list_node{}
    {
    }

    ~sigpending()
    {
        delete info;
    }
#endif
};

static inline bool signal_is_realtime(int sig)
{
    return sig >= KERNEL_SIGRTMIN;
}

static inline bool signal_is_standard(int sig)
{
    return !signal_is_realtime(sig);
}

#define THREAD_SIGNAL_STOPPING        (1 << 0)
#define THREAD_SIGNAL_EXITING         (1 << 1)
#define THREAD_SIGNAL_ORIGINAL_SIGSET (1 << 2)

struct process;

struct signal_info
{
    /* Signal mask */
    sigset_t sigmask;

    struct spinlock lock;

    /* Pending signal set */
    sigset_t pending_set;

    struct list_head pending_head;

    unsigned short flags;

    unsigned long times_interrupted;
    bool signal_pending;

    /* No need for a lock here since any possible changes
     * to this variable happen in kernel mode, in this exact thread.
     */
    stack_t altstack;

    // Used by pselect, ppoll, sigsuspend
    sigset_t original_sigset;

#ifdef __cplusplus

private:
    bool is_signal_pending_internal() const
    {
        const sigset_t &set = pending_set;
        const sigset_t &blocked_set = sigmask;
        sigset_t temp = blocked_set;
        signotset(&temp);
        sigset_t s;
        sigandset(&s, &set, &temp);

        return !sigisemptyset(&s);
    }

public:
    sigset_t get_mask()
    {
        scoped_lock g{lock};
        return sigmask;
    }

    sigset_t get_pending_set()
    {
        scoped_lock g{lock};
        return pending_set;
    }

    sigset_t get_effective_pending()
    {
        scoped_lock g{lock};
        auto set = get_pending_set();
        auto blocked_set = get_mask();
        sigandset(&set, &set, &blocked_set);

        return set;
    }

    sigset_t __add_blocked(const sigset_t *blocked, bool update_pending = true)
    {
        auto old = sigmask;
        sigorset(&sigmask, &sigmask, blocked);
        sigdelset(&sigmask, SIGKILL);
        sigdelset(&sigmask, SIGSTOP);

        if (update_pending)
            __update_pending();
        return old;
    }

    sigset_t add_blocked(const sigset_t *blocked, bool update_pending = true)
    {
        scoped_lock g{lock};
        return __add_blocked(blocked, update_pending);
    }

    sigset_t set_blocked(const sigset_t *blocked, bool update_pending = true)
    {
        scoped_lock g{lock};
        auto old = sigmask;
        memcpy(&sigmask, blocked, sizeof(sigset_t));
        sigdelset(&sigmask, SIGKILL);
        sigdelset(&sigmask, SIGSTOP);

        if (update_pending)
            __update_pending();
        return old;
    }

    sigset_t unblock(sigset_t &mask, bool update_pending = true)
    {
        scoped_lock g{lock};
        auto old = sigmask;
        signotset(&mask);
        sigandset(&sigmask, &sigmask, &mask);

        if (update_pending)
            __update_pending();
        return old;
    }

    void __update_pending()
    {
        MUST_HOLD_LOCK(&lock);

        signal_pending = flags != 0 || is_signal_pending_internal();
    }

    void update_pending()
    {
        scoped_lock g{lock};
        __update_pending();
    }

    void reroute_signals(process *p);

    bool add_pending(struct sigpending *pend)
    {
        scoped_lock g{lock};

        if (signal_is_standard(pend->signum) && sigismember(&pending_set, pend->signum))
            return false;

        list_add(&pend->list_node, &pending_head);

        sigaddset(&pending_set, pend->signum);

        if (!sigismember(&sigmask, pend->signum))
            signal_pending = true;

        return true;
    }

    bool try_to_route(struct sigpending *pend)
    {
        scoped_lock g{lock};

        if (sigismember(&sigmask, pend->signum))
            return false;

        if (signal_is_standard(pend->signum) && sigismember(&pending_set, pend->signum))
            return false;

        list_add(&pend->list_node, &pending_head);
        sigaddset(&pending_set, pend->signum);
        signal_pending = true;

        return true;
    }

    constexpr signal_info()
        : sigmask{}, lock{}, pending_set{}, pending_head{}, flags{}, times_interrupted{},
          signal_pending{}, altstack{}
    {
        INIT_LIST_HEAD(&pending_head);
        altstack.ss_flags = SS_DISABLE;
    }

    ~signal_info();
#endif
};

#define SIGNAL_GROUP_STOPPED (1 << 0)
#define SIGNAL_GROUP_CONT    (1 << 1)
#define SIGNAL_GROUP_EXIT    (1 << 2)

struct process;
struct thread;

bool signal_is_pending(void);
int signal_setup_context(struct sigpending *pend, struct k_sigaction *k_sigaction,
                         struct registers *regs);
void handle_signal(struct registers *regs);

#define SIGNAL_FORCE        (1 << 0)
#define SIGNAL_IN_BROADCAST (1 << 1)

int kernel_raise_signal(int sig, struct process *process, unsigned int flags, siginfo_t *info);
int kernel_tkill(int signal, struct thread *thread, unsigned int flags, siginfo_t *info);
int signal_kill_pg(int sig, int flags, siginfo_t *info, pid_t pid);
void signal_context_init(struct thread *new_thread);
void signal_do_execve(struct process *proc);
int may_kill(int signum, struct process *target, siginfo_t *info);

static inline bool signal_is_stopping(int sig)
{
    return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU;
}

__END_CDECLS

#endif
