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
#ifndef _KERNEL_SIGNAL_H
#define _KERNEL_SIGNAL_H

#include <signal.h>

struct signal_info
{
	int signum;
	int type;
	sighandler_t handler;
};
int sys_kill(pid_t pid, int sig);

#endif