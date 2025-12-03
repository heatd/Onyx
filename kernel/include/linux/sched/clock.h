#ifndef _LINUX_SCHED_CLOCK_H
#define _LINUX_SCHED_CLOCK_H

#include <linux/types.h>
#include <asm/bug.h>

static inline u64 sched_clock(void)
{
    WARN_ON_ONCE(1);
    return 0;
}

#endif
