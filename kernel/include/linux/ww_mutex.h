#ifndef _LINUX_WW_MUTEX_H
#define _LINUX_WW_MUTEX_H

#include <stdbool.h>

#include <onyx/bug.h>
#include <linux/lockdep.h>
struct ww_acquire_ctx
{
};

struct ww_mutex
{
};

static inline bool ww_mutex_is_locked(struct ww_mutex *ww)
{
    WARN_ON(1);
    return false;
}

#endif
