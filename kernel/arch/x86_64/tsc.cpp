/*
 * Copyright (c) 2017 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define pr_fmt(fmt) "x86/tsc: " fmt
#include <fractions.h>
#include <stdbool.h>
#include <stdint.h>

#include <onyx/bug.h>
#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/log.h>
#include <onyx/panic.h>
#include <onyx/timer.h>
#include <onyx/x86/tsc.h>

#include <fixed_point/fixed_point.h>

static struct fp_32_64 ticks_per_ns;
static struct fp_32_64 ns_per_tick;
static u32 tsc_mult, tsc_shift;
static u32 tsc_remult, tsc_reshift;

uint64_t tsc_get_ticks(void);
hrtime_t tsc_elapsed_ns(hrtime_t start, hrtime_t end);
hrtime_t tsc_get_ns(void);

struct clocksource tsc_clock = {
    .name = "tsc",
    .rating = 350,
    .resolution = 64,
    .get_ticks = rdtsc,
    .get_ns = tsc_get_ns,
    .elapsed_ns = tsc_elapsed_ns,
};

#define TSC_MAX_COUNT UINT64_MAX

static PER_CPU_VAR(u64 last_cycle);
static PER_CPU_VAR(u64 last_ns);

hrtime_t tsc_get_ns(void)
{
    unsigned long flags = irq_save_and_disable();
    hrtime_t ns;
    u64 delta, last_ns_;
    u64 ticks = rdtsc();

    WARN_ON(ticks < get_per_cpu(last_cycle));
    delta = ticks - get_per_cpu(last_cycle);
    WRITE_ONCE(tsc_clock.last_cycle, ticks);
    last_ns_ = get_per_cpu(last_ns);
    ns = last_ns_ + ((delta * tsc_mult) >> tsc_shift);
    write_per_cpu(last_cycle, ticks);
    write_per_cpu(last_ns, ns);
    ns += tsc_clock.base + tsc_clock.monotonic_warp;
    irq_restore(flags);
    return ns;
}

hrtime_t tsc_get_counter_from_ns(hrtime_t t)
{
    long delta = t - clocksource_get_time();
    if (delta <= 0)
        delta = 16;
    return (delta * tsc_remult) >> tsc_reshift;
}

/**
 * clocks_calc_mult_shift - calculate mult/shift factors for scaled math of clocks
 * @mult:	pointer to mult variable
 * @shift:	pointer to shift variable
 * @from:	frequency to convert from
 * @to:		frequency to convert to
 * @maxsec:	guaranteed runtime conversion range in seconds
 *
 * The function evaluates the shift/mult pair for the scaled math
 * operations of clocksources and clockevents.
 *
 * @to and @from are frequency values in HZ. For clock sources @to is
 * NSEC_PER_SEC == 1GHz and @from is the counter frequency. For clock
 * event @to is the counter frequency and @from is NSEC_PER_SEC.
 *
 * The @maxsec conversion range argument controls the time frame in
 * seconds which must be covered by the runtime conversion with the
 * calculated mult and shift factors. This guarantees that no 64bit
 * overflow happens when the input value of the conversion is
 * multiplied with the calculated mult factor. Larger ranges may
 * reduce the conversion accuracy by choosing smaller mult and shift
 * factors.
 */
void clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec)
{
    u64 tmp;
    u32 sft, sftacc = 32;

    /*
     * Calculate the shift factor which is limiting the conversion
     * range:
     */
    tmp = ((u64) maxsec * from) >> 32;
    while (tmp)
    {
        tmp >>= 1;
        sftacc--;
    }

    /*
     * Find the conversion shift/mult pair which has the best
     * accuracy and fits the maxsec conversion range:
     */
    for (sft = 32; sft > 0; sft--)
    {
        tmp = (u64) to << sft;
        tmp += from / 2;
        tmp /= from;
        if ((tmp >> sftacc) == 0)
            break;
    }
    *mult = tmp;
    *shift = sft;
}

static bool tsc_enabled = false;

static void do_tsc_freq(u32 freq, u32 scale)
{
    u64 sec;
    /*
     * Calc the maximum number of seconds which we can run before
     * wrapping around. For clocksources which have a mask > 32-bit
     * we need to limit the max sleep time to have a good
     * conversion precision. 10 minutes is still a reasonable
     * amount. That results in a shift value of 24 for a
     * clocksource with mask >= 40-bit and f >= 4GHz. That maps to
     * ~ 0.06ppm granularity for NTP.
     */
    sec = TSC_MAX_COUNT;
    sec /= freq;
    sec /= scale;
    if (!sec)
        sec = 1;
    else if (sec > 600 && /* cs->mask > UINT_MAX */ true)
        sec = 600;

    clocks_calc_mult_shift(&tsc_mult, &tsc_shift, freq, NS_PER_SEC / scale, sec * scale);
    clocks_calc_mult_shift(&tsc_remult, &tsc_reshift, NS_PER_SEC / scale, freq, sec * scale);
}

void tsc_init(void)
{
    u64 freq;
    if (!x86_has_usable_tsc())
    {
        pr_info("Invariant/Constant TSC not available - tsc is not able to be used as a clock source\n");
        return;
    }
    
    freq = x86_get_tsc_rate();
    do_tsc_freq(freq / 1000, 1000);
    pr_info("Frequency: %lu Hz\n", freq);

    fp_32_64_div_32_32(&ns_per_tick, (uint32_t) min(freq, (u64) UINT32_MAX), NS_PER_SEC);
    fp_32_64_div_32_32(&ticks_per_ns, NS_PER_SEC, (uint32_t) min(freq, (u64) UINT32_MAX));

    // printk("ticks per ns: %lu/%lu\n", ticks_per_ns.numerator, ticks_per_ns.denominator);

    tsc_clock.rate = freq;
    tsc_clock.monotonic_warp = -((rdtsc() * tsc_mult) >> tsc_shift);
    tsc_clock.last_cycle = rdtsc();
    tsc_clock.ticks_per_ns = &ticks_per_ns;

    register_clock_source(&tsc_clock);

    tsc_enabled = true;
}

hrtime_t tsc_elapsed_ns(hrtime_t start, hrtime_t end)
{
    hrtime_t delta = clock_delta_calc(start, end);
    return (delta * tsc_mult) >> tsc_shift;
}

void tsc_setup_vdso(struct vdso_time *time)
{
    if (!tsc_enabled)
        return;
    time->mult = tsc_mult;
    time->shift = tsc_shift;
    time->using_tsc = x86_has_usable_tsc();
}
