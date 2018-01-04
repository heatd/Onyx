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

#include <onyx/x86/tsc.h>

static unsigned int ticks_per_ns;

uint64_t tsc_get_ticks(void);
unsigned int tsc_elapsed_ns(uint64_t start, uint64_t end);

struct clocksource tsc_clock = 
{
	.name = "tsc",
	.rating = 350,
	.get_ticks = rdtsc,
	.elapsed_ns = tsc_elapsed_ns
};

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

	ticks_per_ns = freq / NS_PER_SEC;

	tsc_clock.rate = freq;
	register_clock_source(&tsc_clock);
}

unsigned int tsc_elapsed_ns(uint64_t start, uint64_t end)
{
	uint64_t delta = clock_delta_calc(start, end);
	return delta / ticks_per_ns;
}

void tsc_setup_vdso(struct vdso_time *time)
{
	time->ticks_per_ns = ticks_per_ns;
	time->using_tsc = x86_check_invariant_tsc();
}
