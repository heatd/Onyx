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
#include <errno.h>

#include <kernel/timer.h>
#include <drivers/rtc.h>
#include <kernel/vmm.h>
#include <sys/time.h>
time_t sys_time(time_t *s)
{
	if(vmm_check_pointer(s, sizeof(time_t)) == 0)
		*s = get_posix_time();
	return get_posix_time();
}
int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	if(tv)
	{
		if(vmm_check_pointer(tv, sizeof(struct timeval)) < 0)
			return errno = -EFAULT;
		tv->tv_sec = get_posix_time();
		tv->tv_usec = get_posix_time() * 1000 + get_microseconds();
	}
	if(tz)
	{
		if(vmm_check_pointer(tv, sizeof(struct timezone)) < 0)
			return errno = -EFAULT;
		tz->tz_minuteswest = 0;
		tz->tz_dsttime = 0; 
	}
	return 0;
}