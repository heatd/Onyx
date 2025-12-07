/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/completion.h>
#include <linux/minmax.h>
#include <linux/sched.h>

unsigned long wait_for_completion_timeout(struct completion *comp, unsigned long timeout)
{
    hrtime_t now, deadline;
    unsigned long ret;
    int err;

    now = clocksource_get_time();
    deadline = now + (timeout * NS_PER_MS);

    err = wait_for_event_timeout(&comp->wait, comp->done == 1, timeout * NS_PER_MS);
    if (err)
        return 0;
    ret = (deadline - clocksource_get_time()) / NS_PER_MS;
    return max(ret, 1UL);
}
