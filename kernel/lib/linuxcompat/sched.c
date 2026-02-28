/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/sched.h>

long schedule_timeout(long timeout)
{
    hrtime_t expires;
    s64 diff;

    if (timeout == MAX_SCHEDULE_TIMEOUT)
    {
        sched_yield();
        return timeout;
    }
    else if (WARN_ON(timeout < 0))
        return 0;

    expires = clocksource_get_time() + timeout * NS_PER_MS;
    sched_sleep_ms(timeout);
    diff = expires - clocksource_get_time();
    return diff / NS_PER_MS;
}
