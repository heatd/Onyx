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
#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wunused-parameter"
int gettimeofday (struct timeval *__restrict tm, void *__restrict tz)
{
	return 0;
}
time_t time(time_t *t)
{
	return 0;
}
#pragma GCC pop_options
