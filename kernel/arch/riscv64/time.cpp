/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/device_tree.h>
#include <onyx/riscv/intrinsics.h>
#include <onyx/riscv/sbi.h>
#include <onyx/timer.h>

#include <fixed_point/fixed_point.h>

static fp_32_64 ticks_per_ns;
static fp_32_64 ns_per_tick;
hrtime_t riscv_timer_get_ns();

hrtime_t riscv_timer_elapsed_ns(hrtime_t start, hrtime_t end);

struct clocksource riscv_clock = {
    .name = "riscv-cpu-clock",
    .rating = 350,
    .resolution = 64,
    .get_ticks = riscv_get_time,
    .get_ns = riscv_timer_get_ns,
    .elapsed_ns = riscv_timer_elapsed_ns,
};

hrtime_t riscv_timer_get_ns()
{
    hrtime_t ticks = riscv_get_time();

    riscv_clock.last_cycle = ticks;

    return riscv_clock.base + riscv_clock.monotonic_warp + u64_mul_u64_fp32_64(ticks, ticks_per_ns);
}

hrtime_t riscv_timer_elapsed_ns(hrtime_t start, hrtime_t end)
{
    hrtime_t delta = clock_delta_calc(start, end);
    return u64_mul_u64_fp32_64(delta, ticks_per_ns);
}

PER_CPU_VAR(struct timer riscv_timer);

hrtime_t riscv_get_counter_from_ns(hrtime_t t)
{
    hrtime_t riscv_ns_time = t - riscv_clock.base - riscv_clock.monotonic_warp;
    if (t > riscv_ns_time)
    {
        return UINT64_MAX;
    }

    return u64_mul_u64_fp32_64(riscv_ns_time, ns_per_tick);
}

void riscv_timer_set_oneshot(hrtime_t in_future)
{
    auto now = riscv_timer_get_ns();
    if (now > in_future)
        in_future = now + 100;

    const auto future_timestamp = riscv_get_counter_from_ns(in_future);

    sbi_set_timer(future_timestamp);
}

void riscv_timer_set_periodic(unsigned long freq)
{
    // TODO: The core kernel never uses periodic interrupts
    // We should implement this, but right now it's not really a thing we should worry about
}

void platform_init_clockevents(void)
{
    struct timer *this_timer = get_per_cpu_ptr(riscv_timer);
    this_timer->set_oneshot = riscv_timer_set_oneshot;
    this_timer->set_periodic = riscv_timer_set_periodic;

    this_timer->name = "riscv timer";

    if (this_timer->next_event)
    {
        this_timer->set_oneshot(this_timer->next_event);
    }
    else
    {
        this_timer->next_event = TIMER_NEXT_EVENT_NOT_PENDING;
        INIT_LIST_HEAD(&this_timer->event_list);
    }
}

struct timer *platform_get_timer(void)
{
    struct timer *this_timer = get_per_cpu_ptr(riscv_timer);

    return this_timer;
}

void riscv_timer_irq()
{
    timer_handle_events(get_per_cpu_ptr(riscv_timer));
}

void test_ev(clockevent *ev)
{
    printk("1 second\n");
}

/**
 * @brief Initialise timekeeping and timer functionality in RISCV
 *
 */
void time_init()
{
    irq_enable();
    uint32_t freq;
    auto cpus = device_tree::open_node("/cpus");
    if (!cpus)
        panic("Error getting timebase-frequency: /cpus not found\n");

    int st = cpus->get_property("timebase-frequency", &freq);
    if (st == 0)
    {
        printk("Timer frequency: %u Hz\n", freq);
    }
    else
    {
        panic("Error getting timebase-frequency: %s\n", fdt_strerror(st));
    }

    fp_32_64_div_32_32(&ns_per_tick, (uint32_t) freq, NS_PER_SEC);

    fp_32_64_div_32_32(&ticks_per_ns, NS_PER_SEC, (uint32_t) freq);

    riscv_clock.rate = freq;
    riscv_clock.monotonic_warp = -u64_mul_u64_fp32_64(riscv_get_time(), ticks_per_ns);
    riscv_clock.last_cycle = riscv_get_time();
    riscv_clock.ticks_per_ns = &ticks_per_ns;

    platform_init_clockevents();

    register_clock_source(&riscv_clock);

    riscv_or_csr(RISCV_SIE, RISCV_SIE_STIE);
    printk("Waiting a second\n");
    clockevent ev;
    ev.callback = test_ev;
    ev.deadline = clocksource_get_time() + NS_PER_SEC;
    ev.flags = 0;

    timer_queue_clockevent(&ev);

    while (true)
    {
        __asm__ __volatile__("wfi");
    }
}
