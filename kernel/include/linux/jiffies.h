#ifndef _LINUX_JIFFIES_H
#define _LINUX_JIFFIES_H

#include <asm/param.h>
#include <linux/minmax.h>
#include <linux/types.h>
#include <linux/time64.h>

#include <onyx/clock.h>

static inline u64 nsecs_to_jiffies64(u64 n)
{
    return n / NS_PER_MS;
}

static inline unsigned long msecs_to_jiffies(unsigned int m)
{
    return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
}

extern unsigned long jiffies;

#endif
