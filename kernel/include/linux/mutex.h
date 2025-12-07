#ifndef _LINUX_MUTEX_H
#define _LINUX_MUTEX_H

#include <onyx/mutex.h>
#include <linux/list.h>
#include <linux/cleanup.h>
#include <linux/sched.h>

#include <asm/current.h>
#include <asm/processor.h>

DEFINE_GUARD(mutex, struct mutex *, mutex_lock(_T), mutex_unlock(_T))
DEFINE_GUARD_COND(mutex, _try, mutex_trylock(_T))
DEFINE_GUARD_COND(mutex, _intr, mutex_lock_interruptible(_T), _RET == 0)

#define DEFINE_MUTEX(mutex) DECLARE_MUTEX(mutex)

#define mutex_destroy(mutex) do { (void) (mutex); } while (0)

static inline bool mutex_is_locked(struct mutex *lock)
{
    return lock->counter > 0;
}

#endif
