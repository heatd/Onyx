/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>

#include <onyx/assert.h>
#include <onyx/device_tree.h>
#include <onyx/init.h>
#include <onyx/intrinsics.h>
#include <onyx/irq.h>
#include <onyx/timer.h>
#include <onyx/types.h>

hrtime_t arm64_get_time()
{
    return mrs(REG_CNTPCT);
}

#define TIMER_CVAL "cntv_cval_el0"
#define TIMER_CTL  "cntv_ctl_el0"

#define TIMER_CTL_ENABLE  (1 << 0)
#define TIMER_CTL_IMASK   (1 << 1)
#define TIMER_CTL_ISTATUS (1 << 2)

static fp_32_64 ticks_per_ns;
static fp_32_64 ns_per_tick;
hrtime_t arm64_timer_get_ns();

hrtime_t arm64_timer_elapsed_ns(hrtime_t start, hrtime_t end);

struct clocksource arm64_clock = {
    .name = " arm64-cpu-clock",
    .rating = 350,
    .resolution = 64,
    .get_ticks = arm64_get_time,
    .get_ns = arm64_timer_get_ns,
    .elapsed_ns = arm64_timer_elapsed_ns,
};

hrtime_t arm64_timer_get_ns()
{
    hrtime_t ticks = arm64_get_time();

    arm64_clock.last_cycle = ticks;

    return arm64_clock.base + arm64_clock.monotonic_warp + u64_mul_u64_fp32_64(ticks, ticks_per_ns);
}

hrtime_t arm64_timer_elapsed_ns(hrtime_t start, hrtime_t end)
{
    hrtime_t delta = clock_delta_calc(start, end);
    return u64_mul_u64_fp32_64(delta, ticks_per_ns);
}

PER_CPU_VAR(struct timer arm64_timer);

hrtime_t arm64_get_counter_from_ns(hrtime_t t)
{
    hrtime_t arm64_ns_time = t - arm64_clock.base - arm64_clock.monotonic_warp;
    if (t > arm64_ns_time)
    {
        return UINT64_MAX;
    }

    return u64_mul_u64_fp32_64(arm64_ns_time, ns_per_tick);
}

void arm64_timer_set_oneshot(hrtime_t in_future)
{
    auto now = arm64_timer_get_ns();
    if (now > in_future)
        in_future = now + 100;

    const auto future_timestamp = arm64_get_counter_from_ns(in_future);
    msr(TIMER_CVAL, future_timestamp);
}

void arm64_timer_set_periodic(unsigned long freq)
{
    // TODO: The core kernel never uses periodic interrupts
    // We should implement this, but right now it's not really a thing we should worry about
    CHECK(0);
}

void arm64_timer_enable_irqs()
{
    // Enable IRQs and the timer itself
    msr(TIMER_CTL, TIMER_CTL_ENABLE);
}

void platform_init_clockevents()
{
    struct timer *this_timer = get_per_cpu_ptr(arm64_timer);
    this_timer->set_oneshot = arm64_timer_set_oneshot;
    this_timer->set_periodic = arm64_timer_set_periodic;

    this_timer->name = "arm64 timer";

    if (this_timer->next_event)
    {
        this_timer->set_oneshot(this_timer->next_event);
    }
    else
    {
        this_timer->next_event = TIMER_NEXT_EVENT_NOT_PENDING;
        INIT_LIST_HEAD(&this_timer->event_list);
    }

    arm64_timer_enable_irqs();
}

struct timer *platform_get_timer()
{
    struct timer *this_timer = get_per_cpu_ptr(arm64_timer);

    return this_timer;
}

static void clock_init()
{
    u64 freq = mrs(REG_CNTFRQ);
    printk("arm64: timer frequency: %luHz\n", freq);

    fp_32_64_div_32_32(&ns_per_tick, (uint32_t) freq, NS_PER_SEC);

    fp_32_64_div_32_32(&ticks_per_ns, NS_PER_SEC, (uint32_t) freq);

    arm64_clock.rate = freq;
    arm64_clock.monotonic_warp = -u64_mul_u64_fp32_64(arm64_get_time(), ticks_per_ns);
    arm64_clock.last_cycle = arm64_get_time();
    arm64_clock.ticks_per_ns = &ticks_per_ns;

    register_clock_source(&arm64_clock);
}

irqstatus_t arm64_irq_timer(struct irq_context *ctx, void *cookie)
{
    timer_handle_events(get_per_cpu_ptr(arm64_timer));

    return IRQ_HANDLED;
}

static struct driver driver = {
    .name = "arm64_generic_timer", .devids = nullptr, .probe = nullptr, .bus_type_node = {&driver}};

void arm64_timer_init()
{
    // TODO(pedro): incorporate this into device tree device probing code
    auto dev = device_tree::open_node("/timer");
    driver_register_device(&driver, dev);

    // TODO(pedro): We don't know if we're hooked up to IRQ27. While we likely are, please see the
    // device tree.
    install_irq(27, arm64_irq_timer, dev, IRQ_FLAG_REGULAR, nullptr);

    platform_init_clockevents();

    clock_init();
}

INIT_LEVEL_CORE_PLATFORM_ENTRY(arm64_timer_init);
