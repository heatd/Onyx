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
#include <stdio.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/syscall.h>
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	syscall(SYS_gettimeofday, tv, tz);
	if(rax == (unsigned long) -1)
	{
		set_errno();
	}
	return rax;
}
time_t time(time_t *t)
{
	syscall(SYS_time, t);
	if(rax == (unsigned long) -1)
	{
		set_errno();
	}
	return (time_t) rax;
}
