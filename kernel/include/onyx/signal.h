/*
* Copyright (c) 2016-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_SIGNAL_H
#define _ONYX_SIGNAL_H


#include <signal.h>
#include <stdbool.h>

#include <onyx/list.h>

#ifdef __cplusplus
#include <onyx/scoped_lock.h>
#endif

#define KERNEL_SIGRTMIN				32
#define KERNEL_SIGRTMAX				64

#ifdef __cplusplus
extern "C"
void signotset(sigset_t *set);
#endif

struct sigpending
{
	siginfo_t *info;
	int signum;
	struct list_head list_node;
};

struct signal_info
{
	/* Signal mask */
	sigset_t sigmask;

	struct spinlock lock;
	
	/* Pending signal set */
	sigset_t pending_set;

	struct list_head pending_head;

	/* Symbolizes if a signal is pending or not */
	bool signal_pending;

	/* No need for a lock here since any possible changes
	 * to this variable happen in kernel mode, in this exact thread.
	 */
	stack_t altstack;

#ifdef __cplusplus

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

		if(update_pending) __update_pending();
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

		if(update_pending) __update_pending();
		return old;
	}

	sigset_t unblock(sigset_t& mask, bool update_pending = true)
	{
		scoped_lock g{lock};
		auto old = sigmask;
		signotset(&mask);
		sigandset(&sigmask, &sigmask, &mask);

		if(update_pending) __update_pending();
		return old;
	}

	void __update_pending()
	{
		MUST_HOLD_LOCK(&lock);
		const sigset_t& set = pending_set;
		const sigset_t& blocked_set = sigmask;

		bool is_pending = false;

		for(int i = 0; i < NSIG; i++)
		{
			if(sigismember(&set, i) && !sigismember(&blocked_set, i))
			{
				is_pending = true;
				break;
			}
		}

		signal_pending = is_pending;
	}

	void update_pending()
	{
		scoped_lock g{lock};
		__update_pending();
	}

#endif
};

#define SIGNAL_GROUP_STOP_PENDING               (1 << 0)
#define SIGNAL_GROUP_CONT_PENDING               (1 << 1)
#define SIGNAL_GROUP_EXIT                       (1 << 2)
#define SIGNAL_GROUP_CONT                       (1 << 3)

struct process;
struct thread;

#ifdef __cplusplus
extern "C" {
#endif

bool signal_is_pending(void);
int signal_setup_context(struct sigpending *pend, struct k_sigaction *k_sigaction, struct registers *regs);
void handle_signal(struct registers *regs);

#define SIGNAL_FORCE                            (1 << 0)
#define SIGNAL_IN_BROADCAST               (1 << 1)

int kernel_raise_signal(int sig, struct process *process, unsigned int flags, siginfo_t *info);
int kernel_tkill(int signal, struct thread *thread, unsigned int flags, siginfo_t *info);
void signal_context_init(struct thread *new_thread);
void signal_do_execve(struct process *proc);

#ifdef __cplusplus
}
#endif

#endif
