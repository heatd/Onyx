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

struct clocksource
{
	const char *name;
	long rating;
	unsigned long rate;
	unsigned int resolution;
	uint64_t (*get_ticks)(void);
	unsigned int (*elapsed_ns)(uint64_t old_ticks, uint64_t new_ticks);
};

struct clock_time
{
	time_t epoch;
	uint64_t tick;
	struct clocksource *source;
};

void register_wallclock_source(struct wallclock_source *clk);
void register_clock_source(struct clocksource *clk);
struct clocksource *get_main_clock(void);
uint64_t clock_delta_calc(uint64_t start, uint64_t end);
void time_set(clockid_t clock, struct clock_time *val);
int clock_gettime_kernel(clockid_t clk_id, struct timespec *tp);
struct clock_time *get_raw_clock_time(clockid_t clkid);

#endif
