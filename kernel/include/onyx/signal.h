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

struct signal_info
{
	int signum;
	int type;
};

struct process;

#ifdef __cplusplus
extern "C" {
#endif

int sys_kill(pid_t pid, int sig);
void kernel_raise_signal(int sig, struct process *process);
bool signal_is_pending(void);

#ifdef __cplusplus
}
#endif

#endif
