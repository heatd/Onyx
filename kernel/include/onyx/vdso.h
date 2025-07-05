/*
 * Copyright (c) 2017 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _KERNEL_VDSO_H
#define _KERNEL_VDSO_H

#include <stdbool.h>
#include <sys/time.h>
#include <time.h>

#include <onyx/clock.h>

#include <fixed_point/fixed_point.h>

struct vdso_time
{
    /* Timer mult and shift parameters - to convert cycles to ns */
    u32 mult, shift;
#ifdef __x86_64__
    bool using_tsc;
#endif
};

struct vdso_clock_time
{
    struct timespec time;
    hrtime_t tick;
};

void vdso_init(void);
void *vdso_map(void);
int vdso_update_time(clockid_t id, struct clock_time *time);

#endif
