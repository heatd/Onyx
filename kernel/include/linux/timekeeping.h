#ifndef _LINUX_TIMEKEEPING_H
#define _LINUX_TIMEKEEPING_H

#include <linux/time.h>
#include <linux/ktime.h>

#include <onyx/compiler.h>
#include <onyx/clock.h>

static inline ktime_t ktime_get(void)
{
    return clocksource_get_time();
}

#endif
