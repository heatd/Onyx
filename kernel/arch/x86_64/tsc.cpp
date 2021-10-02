/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdbool.h>

#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/log.h>
#include <onyx/timer.h>
#include <onyx/panic.h>

#include <fractions.h>

#include <onyx/x86/tsc.h>
#include <fixed_point/fixed_point.h>

static struct fp_32_64 ticks_per_ns;
static struct fp_32_64 ns_per_tick;

uint64_t tsc_get_ticks(void);
hrtime_t tsc_elapsed_ns(hrtime_t start, hrtime_t end);
hrtime_t tsc_get_ns(void);

struct clocksource tsc_clock = 
{
	.name = "tsc",
	.rating = 350,
	.resolution = 64,
	.get_ticks = rdtsc,
	.get_ns = tsc_get_ns,
	.elapsed_ns = tsc_elapsed_ns,
};

#define TSC_MAX_COUNT		UINT64_MAX

hrtime_t tsc_get_ns(void)
{
	hrtime_t ticks = rdtsc();

	/*if(ticks < tsc_clock.last_cycle)
	{
		printk("ticks %lu\n", ticks);
		panic("AHHHHHHH");
		tsc_clock.base += fract_div_u64_fract(TSC_MAX_COUNT, &ticks_per_ns);
	}*/

	tsc_clock.last_cycle = ticks;

	return tsc_clock.base + tsc_clock.monotonic_warp + (u64_mul_u64_fp32_64(ticks, ticks_per_ns));
}

hrtime_t tsc_get_counter_from_ns(hrtime_t t)
{
	hrtime_t tsc_ns_time = t - tsc_clock.base - tsc_clock.monotonic_warp;
	if(t > tsc_ns_time)
	{
		printk("tsc_ns_time bad time\n");
		printk("Base %lx, warp %lx, t %lx, cpu %u\n", tsc_clock.base, tsc_clock.monotonic_warp, t, get_cpu_nr());
		printk("tsc_ns_time: %lx\n", tsc_ns_time);
		panic("bad tsc ns");
	}

	return u64_mul_u64_fp32_64(tsc_ns_time, ns_per_tick);
}

static bool tsc_enabled = false;

#undef TESTING_TSC
void tsc_init(void)
{
	if(!x86_has_usable_tsc())
	{
		INFO("tsc", "Invariant/Constant TSC not available - tsc is not able to be "
		"used as a clock source\n");
		return;
	}
	uint64_t freq = x86_get_tsc_rate();

	INFO("tsc", "Frequency: %lu Hz\n", freq);
	assert(freq <= UINT32_MAX);

	fp_32_64_div_32_32(&ns_per_tick, (uint32_t) freq, NS_PER_SEC);

	fp_32_64_div_32_32(&ticks_per_ns, NS_PER_SEC, (uint32_t) freq);

	//printk("ticks per ns: %lu/%lu\n", ticks_per_ns.numerator, ticks_per_ns.denominator);

	tsc_clock.rate = freq;
	tsc_clock.monotonic_warp = -u64_mul_u64_fp32_64(rdtsc(), ticks_per_ns);
	tsc_clock.last_cycle = rdtsc();
	tsc_clock.ticks_per_ns = &ticks_per_ns;

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
	return u64_mul_u64_fp32_64(delta, ticks_per_ns);
}

void tsc_setup_vdso(struct vdso_time *time)
{
	if(!tsc_enabled)
		return;
	time->ticks_per_ns = ticks_per_ns;
	time->using_tsc = x86_has_usable_tsc();
}
