/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>
#include <time.h>

#include <sys/times.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <onyx/timer.h>
#include <onyx/vmm.h>
#include <onyx/process.h>

#include <drivers/rtc.h>

time_t sys_time(time_t *s)
{
	if(s)
	{
		uint64_t posix = get_posix_time();
		if(copy_to_user(s, &posix, sizeof(time_t)) < 0)
			return -EFAULT;
	}
	return get_posix_time();
}
int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	if(tv)
	{
		struct timeval t;
		t.tv_sec = get_posix_time();
		t.tv_usec = get_posix_time() * 1000 + get_microseconds();
		if(copy_to_user(tv, &t, sizeof(struct timeval)) < 0)
			return -EFAULT;
	}
	return 0;
}
int sys_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	struct timespec t;
	switch(clk_id)
	{
		case CLOCK_REALTIME:
		{
			t.tv_sec = get_posix_time();
			t.tv_nsec = get_microseconds();
			break;
		}
		case CLOCK_MONOTONIC:
		{
			t.tv_sec = get_tick_count() / 1000;
			t.tv_nsec = get_microseconds() * 1000;
			break;
		}
		default:
			return -EINVAL;
	}
	if(copy_to_user(tp, &t, sizeof(struct timespec)) < 0)
		return -EFAULT;
	return 0;
}
clock_t sys_times(struct tms *buf)
{
	struct process *current = get_current_process();
	struct tms b = {0};
	b.tms_stime = current->system_time;
	b.tms_utime = current->user_time;
	if(copy_to_user(buf, &b, sizeof(struct tms)) < 0)
		return -EFAULT;
	return get_tick_count();
}
int sys_getrusage(int who, struct rusage *usage)
{
	return -ENOSYS;
}
