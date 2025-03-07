/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_SIGNAL_H
#define _ONYX_SIGNAL_H

#include <stdbool.h>

#include <onyx/list.h>
#include <onyx/ref.h>
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
};

struct arch_siginfo
{
    siginfo_t info;
    int signum;
    struct k_sigaction action;
};

static inline bool signal_is_realtime(int sig)
{
    return sig >= KERNEL_SIGRTMIN;
}

static inline bool signal_is_standard(int sig)
{
    return !signal_is_realtime(sig);
}

#define THREAD_SIGNAL_STOPPING (1 << 0)
#define THREAD_SIGNAL_EXITING  (1 << 1)

struct sighand_struct
{
    refcount_t refs;
    struct spinlock signal_lock;
    struct k_sigaction sigtable[_NSIG];
};

/* Note: sigtable not initialized */
static inline void sighand_init(struct sighand_struct *s)
{
    s->refs = REFCOUNT_INIT(1);
    spin_lock_init(&s->signal_lock);
}

struct process;

struct sigqueue
{
    /* Note: pending, pending_head are protected by sighand->signal_lock */
    sigset_t pending;
    struct list_head pending_head;
};

static inline void sigqueue_init(struct sigqueue *queue)
{
    queue->pending = (sigset_t){};
    INIT_LIST_HEAD(&queue->pending_head);
}

#define SIGNAL_GROUP_STOPPED (1 << 0)
/* SIGNAL_GROUP_PENDING is set when there's a CONT status to reap (since we last looked at this
 * process in wait4). */
#define SIGNAL_GROUP_CONT    (1 << 1)
#define SIGNAL_GROUP_EXIT    (1 << 2)

/* We set CONT_PENDING if we're pending the parent notification on SIGCONT. It is set when sending
 * SIGCONT. */
#define SIGNAL_GROUP_CONT_PENDING (1 << 3)

struct process;
struct thread;

bool signal_is_pending(void);
bool find_signal(struct arch_siginfo *sinfo);
void signal_end_delivery(struct arch_siginfo *sinfo);

#define SIGNAL_FORCE        (1 << 0)
#define SIGNAL_IN_BROADCAST (1 << 1)

int kernel_raise_signal(int sig, struct process *process, unsigned int flags, siginfo_t *info);
int signal_kill_pg(int sig, int flags, siginfo_t *info, pid_t pid);
void signal_context_init(struct thread *new_thread);
void signal_do_execve(struct process *proc);
int may_kill(int signum, struct process *target, siginfo_t *info);

static inline bool signal_is_stopping(int sig)
{
    return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU;
}

static inline void sigaltstack_init(stack_t *stack)
{
    stack->ss_size = 0;
    stack->ss_sp = NULL;
    stack->ss_flags = SS_DISABLE;
}

struct syscall_frame;
bool executing_in_altstack(const struct syscall_frame *frm, const stack_t *stack);

int raise_sig_thr(int sig, struct process *task, unsigned int flags, siginfo_t *info);
int raise_sig_curthr(int sig, unsigned int flags, siginfo_t *info);

/**
 * @brief Low-level helper for signal-related code (do not use, probably)
 * Sets TF_SIGPENDING and tries to wake it up, if possible.
 *
 * @param task Task (thread) to wake up
 * @param signal Signal number
 */
void signal_interrupt_task(struct process *task, int signal);

/* The two following helpers implement saved sigmask semantics for Onyx. System calls that take
 * sigmasks are supposed to use signal_setmask_and_save at the start, and signal_restore_sigmask if
 * not interrupted by a signal. If interrupted by a signal, the signal handling code will save the
 * sigmask on the stack, which will be transparently restored by sigreturn. */

/**
 * @brief Set the mask and store the old one for saving later
 * To be used by syscalls that need such semantics (ppoll, pselect, sigsuspend, etc)
 *
 * @param mask New sigmask
 */
void signal_setmask_and_save(const sigset_t *mask);

/**
 * @brief Restore the saved sigmask
 * To be used by syscalls that need such semantics (ppoll, pselect, sigsuspend, etc)
 *
 */
void signal_restore_sigmask(void);

void signal_setmask(const sigset_t *mask);

/**
 * @brief Notify this task's parent that we're exiting
 * We have to be careful and check if we need to, e.g, autoreap. write_lock needs to be held when
 * calling.
 *
 * @param exit_code Exit code to notify with
 * @retval true If task should be autoreaped (thus no signal was sent, nor did we wake anyone up)
 */
bool parent_notify(unsigned int exit_code);

/**
 * @brief Notify this task's parent that we're stopping/continuing
 * We have to be careful and check if we need to, e.g, not send anything. tasklist read_lock needs
 * to be held when calling.
 *
 * @param exit_code Stop code to notify with
 * @retval true If task was woken up
 */
bool notify_process_stop_cont(struct process *task, unsigned int exit_code);

void force_sigsegv(int sig);

/* Used when forcing signals, such that no one racing with us can change this signal while another
 * thread is trying to catch a fault */
#define SA_IMMUTABLE 0x00800000

__END_CDECLS

#endif
