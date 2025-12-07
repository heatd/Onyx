#ifndef _LINUX_TIMER_TYPES_H
#define _LINUX_TIMER_TYPES_H

#include <linux/types.h>
#include <onyx/timer.h>

struct timer_list
{
    struct clockevent clock_event;
};

#endif
