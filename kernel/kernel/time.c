/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <time.h>
#include <assert.h>

#include <sys/times.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <onyx/vdso.h>
#include <onyx/timer.h>
#include <onyx/vm.h>
#include <onyx/process.h>
#include <onyx/clock.h>

struct wallclock_source *main_wallclock;
struct clocksource *main_clock;

#define NR_CLOCKS	CLOCK_TAI
static struct clock_time clocks[NR_CLOCKS];

void register_wallclock_source(struct wallclock_source *clk)
{
	assert(clk->get_posix_time != NULL);

	main_wallclock = clk;
}

void register_clock_source(struct clocksource *clk)
{
	if(main_clock)
	{
		if(main_clock->rating < clk->rating)
			main_clock = clk;
	}
	else
		main_clock = clk;
}

struct clocksource *get_main_clock(void)
{
	assert(main_clock != NULL);
	return main_clock;
}

hrtime_t clocksource_get_time(void)
{
	return main_clock->get_ns();
}

time_t sys_time(time_t *s)
{
	if(s)
	{
		time_t posix = clocks[CLOCK_REALTIME].epoch;
		if(copy_to_user(s, &posix, sizeof(time_t)) < 0)
			return -EFAULT;
	}
	return clocks[CLOCK_REALTIME].epoch;
}

int clock_gettime_kernel(clockid_t clk_id, struct timespec *tp)
{
	switch(clk_id)
	{
		case CLOCK_REALTIME:
		{
			tp->tv_sec = clocks[clk_id].epoch;
			uint64_t start = clocks[clk_id].tick;
			uint64_t end = clocks[clk_id].source->get_ticks();
			tp->tv_nsec = clocks[clk_id].source->elapsed_ns(start, end);
			break;
		}
		case CLOCK_MONOTONIC:
		{
			tp->tv_sec = clocks[clk_id].epoch;
			uint64_t start = clocks[clk_id].tick;
			uint64_t end = clocks[clk_id].source->get_ticks();
			tp->tv_nsec = clocks[clk_id].source->elapsed_ns(start, end);
			break;
		}
		default:
			return -EINVAL;
	}
	return 0;
}

int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	if(tv)
	{
		struct timespec tp;
		struct timeval t;
		clock_gettime_kernel(CLOCK_REALTIME, &tp);

		t.tv_sec = tp.tv_sec;
		t.tv_usec = tp.tv_nsec / 1000;

		if(copy_to_user(tv, &t, sizeof(struct timeval)) < 0)
			return -EFAULT;
	}
	return 0;
}

int sys_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	struct timespec t;
	int st = clock_gettime_kernel(clk_id, &t);

	if(st < 0)
		return st;

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

uint64_t clock_delta_calc(uint64_t start, uint64_t end)
{
	return end - start;
}

void time_set(clockid_t clock, struct clock_time *val)
{
	clocks[clock] = *val;
	vdso_update_time(clock, val);
}

struct clock_time *get_raw_clock_time(clockid_t clkid)
{
	return &clocks[clkid];
}

time_t clock_get_posix_time(void)
{
	return get_raw_clock_time(CLOCK_REALTIME)->epoch;
}

void ndelay(unsigned int ns)
{
	struct clocksource *c = get_main_clock();
	uint64_t start = c->get_ticks();

	while(c->elapsed_ns(start, c->get_ticks()) < ns);
}

void udelay(unsigned int us)
{
	ndelay(us * 1000);
}
