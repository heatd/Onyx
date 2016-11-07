/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <unistd.h>
#include <signal.h>

#include <sys/syscall.h>
#include <sys/types.h>

int kill(pid_t pid, int sig)
{
	syscall(SYS_kill, pid, sig);
	if(rax == (unsigned long) -1)
	{
		set_errno();
	}
	return rax;
}
int raise(int signal)
{
	return kill(getpid(), signal);
}
void (*signal(int sig, void (*func)(int)))(int)
{
	syscall(sig, func);
	if(rax == (unsigned long) SIG_ERR)
	{
		set_errno();
	}
	return (void(*)(int)) rax;
}