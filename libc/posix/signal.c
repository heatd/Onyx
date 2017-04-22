/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
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

#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wunused-parameter"
int kill(pid_t pid, int sig)
{
	return 0;
}
int raise(int signal)
{
	return kill(getpid(), signal);
}
#pragma GCC pop_options
