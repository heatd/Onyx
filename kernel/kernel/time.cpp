/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>

#include <onyx/clock.h>
#include <onyx/process.h>
#include <onyx/timer.h>
#include <onyx/vdso.h>
#include <onyx/vm.h>

struct wallclock_source *main_wallclock;
struct clocksource *main_clock;

#define NR_CLOCKS CLOCK_TAI
static struct clock_time clocks[NR_CLOCKS];

void register_wallclock_source(struct wallclock_source *clk)
{
    assert(clk->get_posix_time != NULL);

    main_wallclock = clk;
}

void clocksource_calc_max_idle(struct clocksource *clk)
{
    hrtime_t timer_mask = clk->resolution == 64 ? UINT64_MAX : (1UL << clk->resolution) - 1;

    /* Check for possible overflow calculating this */
    if (timer_mask == UINT64_MAX && u64_mul_u64_fp32_64(1, *clk->ticks_per_ns) >= 1)
    {
        clk->max_idle_ns = UINT64_MAX;
        return;
    }

    clk->max_idle_ns = u64_mul_u64_fp32_64(timer_mask, *clk->ticks_per_ns);
}

void clocksource_unidle(struct clockevent *ev)
{
    struct clocksource *s = (clocksource *)ev->priv;
    s->get_ns();
    ev->deadline = clocksource_get_time() + s->max_idle_ns;
}

void register_clock_source(struct clocksource *clk)
{
    if (main_clock)
    {
        if (main_clock->rating < clk->rating)
            main_clock = clk;
    }
    else
        main_clock = clk;

    clocksource_calc_max_idle(clk);
    struct clockevent *ev = (clockevent *)zalloc(sizeof(*ev));
    assert(ev != NULL);

    /* For very nice timesources like the x86's TSC, this will possibly overflow.
     * If so, just set the clockevent to the furthest possible time
     * (UINT64_MAX - 1, because UINT64_MAX is used as TIMER_NEXT_EVENT_NOT_PENDING). */

    if (__builtin_add_overflow(clocksource_get_time(), clk->max_idle_ns, &ev->deadline))
        ev->deadline = TIMER_NEXT_EVENT_NOT_PENDING - 1;
    ev->priv = clk;
    ev->callback = clocksource_unidle;
    ev->flags = CLOCKEVENT_FLAG_ATOMIC | CLOCKEVENT_FLAG_PULSE;

    timer_queue_clockevent(ev);
}

struct clocksource *get_main_clock(void)
{
    assert(main_clock != NULL);
    return main_clock;
}

hrtime_t clocksource_get_time(void)
{
    if (unlikely(!main_clock))
        return 0;
    return main_clock->get_ns();
}

time_t sys_time(time_t *s)
{
    if (s)
    {
        time_t posix = clocks[CLOCK_REALTIME].epoch;
        if (copy_to_user(s, &posix, sizeof(time_t)) < 0)
            return -EFAULT;
    }
    return clocks[CLOCK_REALTIME].epoch;
}

int clock_gettime_kernel(clockid_t clk_id, struct timespec *tp)
{
    switch (clk_id)
    {
    case CLOCK_REALTIME: {
        tp->tv_sec = clocks[clk_id].epoch;
        uint64_t start = clocks[clk_id].tick;
        uint64_t end = clocks[clk_id].source->get_ticks();
        tp->tv_nsec = clocks[clk_id].source->elapsed_ns(start, end);
        break;
    }

    case CLOCK_MONOTONIC:
    case CLOCK_MONOTONIC_RAW: {
        // TODO: This is not conforming
        if (clk_id == CLOCK_MONOTONIC_RAW)
        {
            clk_id = CLOCK_MONOTONIC;
        }

        auto t0 = clocksource_get_time();
        tp->tv_sec = t0 / NS_PER_SEC;
        tp->tv_nsec = t0 % NS_PER_SEC;
        break;
    }

    case CLOCK_PROCESS_CPUTIME_ID: {
        struct process *p = get_current_process();

        hrtime_t total_time = p->system_time + p->user_time;

        hrtime_to_timespec(total_time, tp);
        break;
    }

    case CLOCK_THREAD_CPUTIME_ID: {
        struct thread *thr = get_current_thread();

        hrtime_t total_time = thr->cputime_info.system_time + thr->cputime_info.user_time;
        hrtime_to_timespec(total_time, tp);
        break;
    }

    default:
        return -EINVAL;
    }

    return 0;
}

int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    if (tv)
    {
        struct timespec tp;
        struct timeval t;
        clock_gettime_kernel(CLOCK_REALTIME, &tp);

        t.tv_sec = tp.tv_sec;
        t.tv_usec = tp.tv_nsec / 1000;

        if (copy_to_user(tv, &t, sizeof(struct timeval)) < 0)
            return -EFAULT;
    }
    return 0;
}

int sys_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    struct timespec t;
    int st = clock_gettime_kernel(clk_id, &t);

    if (st < 0)
        return st;

    if (copy_to_user(tp, &t, sizeof(struct timespec)) < 0)
        return -EFAULT;
    return 0;
}

uint64_t clock_delta_calc(uint64_t start, uint64_t end)
{
    return end - start;
}

void time_set(clockid_t clock, struct clock_time *val)
{
    if (clocks[clock].epoch == val->epoch)
        return;

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

    while (c->elapsed_ns(start, c->get_ticks()) < ns)
        ;
}

void udelay(unsigned int us)
{
    ndelay(us * 1000);
}

bool timespec_valid(const struct timespec *ts, bool may_be_negative)
{
    if (ts->tv_nsec >= (long)NS_PER_SEC)
        return false;

    if (may_be_negative)
        return true;

    if (ts->tv_sec < 0)
        return false;
    if (ts->tv_nsec < 0)
        return false;

    return true;
}

bool timeval_valid(const struct timeval *tv, bool may_be_negative)
{
    if (tv->tv_usec >= (long)US_PER_SEC)
        return false;

    if (may_be_negative)
        return true;

    if (tv->tv_sec < 0)
        return false;
    if (tv->tv_usec < 0)
        return false;

    return true;
}
