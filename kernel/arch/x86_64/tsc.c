/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdbool.h>

#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/log.h>
#include <fractions.h>

#include <onyx/x86/tsc.h>

static struct fraction ticks_per_ns;

uint64_t tsc_get_ticks(void);
hrtime_t tsc_elapsed_ns(hrtime_t start, hrtime_t end);
hrtime_t tsc_get_ns(void);

struct clocksource tsc_clock = 
{
	.name = "tsc",
	.rating = 350,
	.get_ticks = rdtsc,
	.get_ns = tsc_get_ns,
	.elapsed_ns = tsc_elapsed_ns
};

#define TSC_MAX_COUNT		UINT64_MAX

hrtime_t tsc_get_ns(void)
{
	hrtime_t ticks = rdtsc();

	if(ticks < tsc_clock.last_cycle)
	{
		tsc_clock.base += fract_div_u64_fract(TSC_MAX_COUNT, &ticks_per_ns);
	}

	tsc_clock.last_cycle = ticks;

	return tsc_clock.base + tsc_clock.monotonic_warp + (fract_div_u64_fract(ticks, &ticks_per_ns));
}

hrtime_t tsc_get_counter_from_ns(hrtime_t t)
{
	hrtime_t tsc_ns_time = t - tsc_clock.base - tsc_clock.monotonic_warp;

	return fract_mult_u64_fract(tsc_ns_time, &ticks_per_ns);
}

#include <onyx/timer.h>

static bool tsc_enabled = false;

#undef TESTING_TSC
void tsc_init(void)
{
	if(x86_check_invariant_tsc() == false)
	{
		INFO("tsc", "Invariant TSC not available - tsc not able to be "
		"used as a clock source\n");
		return;
	}
	uint64_t freq = x86_get_tsc_rate();

	INFO("tsc", "Frequency: %lu Hz\n", freq);

	ticks_per_ns.numerator = freq;
	ticks_per_ns.denominator = NS_PER_SEC;
	fract_reduce(&ticks_per_ns);

	tsc_clock.rate = freq;
	tsc_clock.monotonic_warp = -fract_div_u64_fract(rdtsc(), &ticks_per_ns);
	tsc_clock.last_cycle = rdtsc();
	register_clock_source(&tsc_clock);

	tsc_enabled = true;

#ifdef TESTING_TSC
	//printk("Sleeping. \n");
	//printk("gtc %lu\n", get_tick_count());
	printk("Start %lu\n", get_tick_count());
	unsigned long start = tsc_clock.get_ns();

	while(tsc_clock.get_ns() - start < (NS_PER_SEC * 2));
	printk("Slept. gtc %lu\n", get_tick_count());
#endif
}

hrtime_t tsc_elapsed_ns(hrtime_t start, hrtime_t end)
{
	hrtime_t delta = clock_delta_calc(start, end);
	return fract_div_u64_fract(delta, &ticks_per_ns);
}

void tsc_setup_vdso(struct vdso_time *time)
{
	if(!tsc_enabled)
		return;
	time->ticks_per_ns = fract_get_int(&ticks_per_ns);
	time->using_tsc = x86_check_invariant_tsc();
}
