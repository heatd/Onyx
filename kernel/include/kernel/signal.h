/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SIGNAL_H
#define _KERNEL_SIGNAL_H

#include <signal.h>

typedef void * sighandler_t;
struct signal_info
{
	int signum;
	int type;
};
struct proc;
int sys_kill(pid_t pid, int sig);
void kernel_raise_signal(int sig, struct proc *process);
#endif