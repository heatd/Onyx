/*
 * Copyright (c) 2017 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
/* Define the kernel def so we get the extra defs */
#define __is_onyx_kernel

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <onyx/clock.h>
#include <onyx/vdso.h>
#undef __is_onyx_kernel

#include <fixed_point/fixed_point.h>

struct vdso_info
{
    char name[255];
    char kernel[60];
    char architecture[60];
};

static const struct vdso_info info = {
    .name = "onyx-vdso", .kernel = "onyx-rolling", .architecture = "x86_64"};

long __vdso_syscall(long number, ...);

static struct vdso_info *__vdso_get_vdso_info(void)
{
    return (struct vdso_info *) &info;
}

uint64_t clock_delta_calc(uint64_t start, uint64_t end)
{
    return end - start;
}

volatile struct vdso_clock_time clock_realtime = {0};
volatile struct vdso_clock_time clock_monotonic = {0};
volatile struct vdso_time __time;

unsigned long tsc_elapsed_ns(uint64_t start, uint64_t end)
{
    uint64_t delta = clock_delta_calc(start, end);
    return u64_mul_u64_fp32_64(delta, __time.ticks_per_ns);
}

#define SyS_clock_gettime 42

int __vdso_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    if (!__time.using_tsc)
    {
        /* If we're not using the tsc, just do the system call */
        return __vdso_syscall(SyS_clock_gettime, clk_id, tp);
    }

    volatile struct vdso_clock_time *clk = NULL;
    switch (clk_id)
    {
        case CLOCK_REALTIME: {
            clk = &clock_realtime;
            break;
        }
        case CLOCK_MONOTONIC:
        case CLOCK_MONOTONIC_RAW: {
            clk = &clock_monotonic;
            break;
        }
        default: {
            return __vdso_syscall(SyS_clock_gettime, clk_id, tp);
        }
    }

    hrtime_t elapsed_ns = tsc_elapsed_ns(clk->tick, rdtsc());
    tp->tv_sec = clk->time.tv_sec + elapsed_ns / NS_PER_SEC;
    tp->tv_nsec = clk->time.tv_nsec + elapsed_ns % NS_PER_SEC;
    if (tp->tv_nsec >= NS_PER_SEC)
    {
        tp->tv_sec++;
        tp->tv_nsec %= NS_PER_SEC;
    }

    return 0;
}

time_t __vdso_sys_time(time_t *s)
{
    time_t posix = clock_realtime.time.tv_sec;
    if (s)
        *s = posix;
    return posix;
}

int __vdso_sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    if (tv)
    {
        struct timespec tp;
        struct timeval t;
        __vdso_clock_gettime(CLOCK_REALTIME, &tp);

        tv->tv_sec = tp.tv_sec;
        tv->tv_usec = tp.tv_nsec / 1000;
    }
    return 0;
}
