#ifndef _LINUX_SPINLOCK_H
#define _LINUX_SPINLOCK_H

#include <onyx/spinlock.h>

/* THIS IS A HACK */
typedef struct spinlock arch_spinlock_t;
#define __ARCH_SPIN_LOCK_UNLOCKED {}
#define arch_spin_lock(lock) spin_lock(lock)
#define arch_spin_unlock(lock) spin_unlock(lock)

#endif
