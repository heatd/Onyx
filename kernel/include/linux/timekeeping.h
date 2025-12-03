#ifndef _LINUX_TIMEKEEPING_H
#define _LINUX_TIMEKEEPING_H

#include <linux/time.h>
#include <onyx/compiler.h>

/* TODO: Trivial implementation (monotonic) */
ktime_t ktime_get(void);

#endif
