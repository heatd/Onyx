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

#include <onyx/wait_queue.h>
struct signal_info
{
	/* Signal mask */
	sigset_t sigmask;

	/* Pending signal set */
	sigset_t pending_set;

	/* Symbolizes if a signal is pending or not */
	bool signal_pending;
};

struct process;
struct thread;

#ifdef __cplusplus
extern "C" {
#endif

int sys_kill(pid_t pid, int sig);
void kernel_raise_signal(int sig, struct process *process);
bool signal_is_pending(void);
void signal_setup_context(int sig, struct sigaction *sigaction, struct registers *regs);
void handle_signal(struct registers *regs);
void signal_update_pending(struct thread *thread);
int kernel_tkill(int signal, struct thread *thread);

#ifdef __cplusplus
}
#endif

#endif
