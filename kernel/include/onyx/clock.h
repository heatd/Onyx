/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _KERNEL_CLOCK_H
#define _KERNEL_CLOCK_H

#include <stdint.h>
#include <time.h>

#define NS_PER_SEC 	1000000000UL

struct wallclock_source
{
	const char *clock_source;
	time_t (*get_posix_time)(void);
};

/* hrtime is expressed in units of nanoseconds */
typedef uint64_t hrtime_t;

struct clocksource
{
	const char *name;
	long rating;
	unsigned long rate;
	unsigned int resolution;
	hrtime_t base;
	hrtime_t last_cycle;
	hrtime_t max_idle_ns;
	long monotonic_warp;
	hrtime_t (*get_ticks)(void);
	hrtime_t (*get_ns)(void);
	hrtime_t (*elapsed_ns)(hrtime_t old_ticks, hrtime_t new_ticks);
};

struct clock_time
{
	time_t epoch;
	hrtime_t tick;
	struct clocksource *source;
};

void register_wallclock_source(struct wallclock_source *clk);
void register_clock_source(struct clocksource *clk);
struct clocksource *get_main_clock(void);
hrtime_t clock_delta_calc(hrtime_t start, hrtime_t end);
hrtime_t clock_get_time(struct clocksource *c);
void time_set(clockid_t clock, struct clock_time *val);
int clock_gettime_kernel(clockid_t clk_id, struct timespec *tp);
struct clock_time *get_raw_clock_time(clockid_t clkid);

#endif
