/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _KERNEL_CLOCK_H
#define _KERNEL_CLOCK_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>

#include <sys/time.h>

#include <onyx/compiler.h>

#include <fixed_point/fixed_point.h>

#define US_PER_SEC  1000000UL
#define NS_PER_SEC 	1000000000UL
#define NS_PER_MS	1000000UL
#define NS_PER_US	1000UL

struct wallclock_source
{
	const char *clock_source;
	time_t (*get_posix_time)(void);
};

#ifdef __cplusplus
extern "C" {
#endif

/* hrtime is expressed in units of nanoseconds */
typedef uint64_t hrtime_t;
typedef int64_t hrtime_delta_t;

#define HRTIME_MAX UINT64_MAX

struct clocksource
{
	const char *name;
	long rating;
	unsigned long rate;
	unsigned int resolution;
	hrtime_t base;
	hrtime_t last_cycle;
	hrtime_t max_idle_ns;
	struct fp_32_64 *ticks_per_ns;
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
time_t clock_get_posix_time(void);
hrtime_t clocksource_get_time(void);

bool timespec_valid(const struct timespec *ts, bool may_be_negative);
bool timeval_valid(const struct timeval *tv, bool may_be_negative);

#define timespec_to_hrtime(ts)		((ts)->tv_sec * NS_PER_SEC + (ts)->tv_nsec)

static inline void hrtime_to_timeval(hrtime_t t0, struct timeval *v)
{
	v->tv_sec = t0 / NS_PER_SEC;

	hrtime_t rem = (t0 % NS_PER_SEC);

	v->tv_usec = rem / NS_PER_US;

	/* I think it's pretty reasonable to round up the time */

	if(rem % NS_PER_US)
		v->tv_usec++;
}

static inline hrtime_t timeval_to_hrtime(const struct timeval *v)
{
	hrtime_t sec, usec, res;

	/* Firstly check for multiplication overflow for seconds, then usecs,
	 * then check for overflow while adding both seconds in ns and us in ns.
	 */

	if(unlikely(__builtin_umull_overflow((unsigned long) v->tv_sec, NS_PER_SEC, &sec)))
		return HRTIME_MAX;

	if(unlikely(__builtin_umull_overflow((unsigned long) v->tv_usec, NS_PER_US, &usec)))
		return HRTIME_MAX;

	if(unlikely(__builtin_uaddl_overflow(sec, usec, &res)))
		return HRTIME_MAX;

	return res;
}

#ifdef __cplusplus
}
#endif
#endif
