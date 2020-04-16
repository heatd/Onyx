/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SIGNAL_H
#define _KERNEL_SIGNAL_H

#define _GNU_SOURCE

#include <signal.h>
#include <stdbool.h>

#include <onyx/list.h>

#define KERNEL_SIGRTMIN				32
#define KERNEL_SIGRTMAX				64

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
};

#define SIGNAL_GROUP_STOP_PENDING               (1 << 0)
#define SIGNAL_GROUP_CONT_PENDING               (1 << 1)

struct process;
struct thread;

#ifdef __cplusplus
extern "C" {
#endif

bool signal_is_pending(void);
int signal_setup_context(struct sigpending *pend, struct sigaction *sigaction, struct registers *regs);
void handle_signal(struct registers *regs);
void signal_update_pending(struct thread *thread);

#define SIGNAL_FORCE                            (1 << 0)
#define SIGNAL_IN_BROADCAST               (1 << 1)

int kernel_raise_signal(int sig, struct process *process, unsigned int flags, siginfo_t *info);
int kernel_tkill(int signal, struct thread *thread, unsigned int flags, siginfo_t *info);
void signal_add_to_blocked_set(struct thread *current, sigset_t *new_set);
void signal_set_blocked_set(struct thread *current, sigset_t *new_set);
void signal_context_init(struct thread *new_thread);
void signal_do_execve(struct process *proc);

#ifdef __cplusplus
}
#endif

#endif
