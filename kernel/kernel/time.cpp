/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>

#include <onyx/clock.h>
#include <onyx/date.h>
#include <onyx/kunit.h>
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
    struct clocksource *s = (clocksource *) ev->priv;
    s->get_ns();
    ev->deadline = clocksource_get_time() + s->max_idle_ns;
}

static void sample_wallclock()
{
    if (!main_wallclock)
        return;

    auto now = main_wallclock->get_posix_time();
    struct timespec ts = {.tv_sec = now};
    time_set(CLOCK_REALTIME, &ts);
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
    struct clockevent *ev = (clockevent *) zalloc(sizeof(*ev));
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

    if (main_clock == clk)
    {
        sample_wallclock();
    }
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
        time_t posix = clocks[CLOCK_REALTIME].time.tv_sec;
        if (copy_to_user(s, &posix, sizeof(time_t)) < 0)
            return -EFAULT;
    }
    return clocks[CLOCK_REALTIME].time.tv_sec;
}

int clock_gettime_kernel(clockid_t clk_id, struct timespec *tp)
{
    struct clock_time *clk = &clocks[clk_id];
    switch (clk_id)
    {
        case CLOCK_REALTIME: {
            const hrtime_t now = clocksource_get_time();
            const hrtime_t delta = now - clocks[clk_id].measurement_timestamp;
            tp->tv_sec = clk->time.tv_sec + delta / NS_PER_SEC;
            tp->tv_nsec = clk->time.tv_nsec + delta % NS_PER_SEC;
            while (tp->tv_nsec >= (s64) NS_PER_SEC)
            {
                tp->tv_sec++;
                tp->tv_nsec -= NS_PER_SEC;
            }

            break;
        }

        case CLOCK_MONOTONIC:
        case CLOCK_BOOTTIME:
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
            hrtime_t utime, stime;
            tg_cputime(p, &utime, &stime);
            hrtime_to_timespec(utime + stime, tp);
            break;
        }

        case CLOCK_THREAD_CPUTIME_ID: {
            struct thread *thr = get_current_thread();

            hrtime_t total_time =
                READ_ONCE(thr->cputime_info.system_time) + READ_ONCE(thr->cputime_info.user_time);
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

extern "C" int sys_clock_settime(clockid_t clk_id, struct timespec *utp)
{
    struct timespec tp;

    if (!is_root_user())
        return -EPERM;

    if (copy_from_user(&tp, utp, sizeof(tp)) < 0)
        return -EFAULT;

    /* Filter out bad clocks */
    if (clk_id >= NR_CLOCKS || clk_id < 0)
        return -EINVAL;

    /* And filter out unsettable clocks */
    switch (clk_id)
    {
        case CLOCK_MONOTONIC:
        case CLOCK_MONOTONIC_RAW:
        case CLOCK_MONOTONIC_COARSE:
        case CLOCK_BOOTTIME:
        case CLOCK_BOOTTIME_ALARM:
        case CLOCK_THREAD_CPUTIME_ID:
        case CLOCK_PROCESS_CPUTIME_ID:
        case CLOCK_REALTIME_COARSE:
        case CLOCK_REALTIME_ALARM:
            return -EINVAL;
    }

    time_set(clk_id, &tp);
    return 0;
}

extern "C" int sys_clock_getres(clockid_t clk_id, struct timespec *utp)
{
    /* XXX this is not super correct, and doesn't work with future work on COARSE timers */
    struct timespec tp = {.tv_sec = 0, .tv_nsec = 1};

    /* Filter out bad clocks */
    if (clk_id >= NR_CLOCKS || clk_id < 0)
        return -EINVAL;

    if (copy_to_user(utp, &tp, sizeof(tp)) < 0)
        return -EFAULT;
    return 0;
}

uint64_t clock_delta_calc(uint64_t start, uint64_t end)
{
    return end - start;
}

void time_set(clockid_t clock, struct timespec *ts)
{
    struct clock_time time = {*ts, clocksource_get_time()};
    clocks[clock] = time;
    vdso_update_time(clock, &time);
}

struct clock_time *get_raw_clock_time(clockid_t clkid)
{
    return &clocks[clkid];
}

time_t clock_get_posix_time()
{
    struct timespec tp;
    clock_gettime_kernel(CLOCK_REALTIME, &tp);
    return tp.tv_sec;
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
    if (ts->tv_nsec >= (long) NS_PER_SEC)
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
    if (tv->tv_usec >= (long) US_PER_SEC)
        return false;

    if (may_be_negative)
        return true;

    if (tv->tv_sec < 0)
        return false;
    if (tv->tv_usec < 0)
        return false;

    return true;
}

const int months[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

static bool is_leap_year(int year)
{
    if (year % 4)
        return false;
    // Every year divisible by 4 is a leap year, except when divisible by 100, except when divisible
    // by 400.
    return (year % 100) || ((year % 400) == 0);
}

u64 get_unix_time(const date_t *udate)
{
    u64 utime = 0;
    for (int i = 1970; i < udate->year; i++)
    {
        if (is_leap_year(i))
            utime += 366 * 24 * 60 * 60;
        else
            utime += 365 * 24 * 60 * 60;
    }

    // Calculate this year's POSIX time
    int total_day = 0;
    int month = udate->month - 1;
    assert(month < 12);
    for (int m = 0; m < month; m++)
    {
        if (m == 2 && is_leap_year(udate->year))
            total_day++;
        total_day += months[m];
    }

    total_day += udate->day;

    utime += (total_day - 1) * 86400ULL;
    utime += udate->hours * 60ULL * 60;
    utime += udate->minutes * 60ULL;
    utime += udate->seconds;

    return utime;
}

#ifdef CONFIG_KUNIT

TEST(date, is_leap_year_correct)
{
    EXPECT_TRUE(is_leap_year(1600));
    EXPECT_TRUE(is_leap_year(2000));
    EXPECT_FALSE(is_leap_year(1700));
    EXPECT_FALSE(is_leap_year(1800));
    EXPECT_FALSE(is_leap_year(1900));
    EXPECT_FALSE(is_leap_year(2002));
}

#endif
