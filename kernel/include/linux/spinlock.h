#ifndef _LINUX_SPINLOCK_H
#define _LINUX_SPINLOCK_H

#include <onyx/spinlock.h>
#include <linux/preempt.h>

/* THIS IS A HACK */
typedef struct spinlock arch_spinlock_t;
#define __ARCH_SPIN_LOCK_UNLOCKED {}
#define arch_spin_lock(lock) spin_lock(lock)
#define arch_spin_unlock(lock) spin_unlock(lock)

#define spin_lock_bh(lock) spin_lock(lock)
#define spin_unlock_bh(lock) spin_unlock(lock)

#define raw_spinlock spinlock
#define raw_spin_lock_init(lock) spin_lock_init(lock)

static inline void spin_lock_irq(struct spinlock *lock) __ACQUIRE(lock)
{
    irq_disable();
    __spin_lock(lock);
}

static inline void spin_unlock_irq(struct spinlock *lock)
    __RELEASE(lock)
{
    __spin_unlock(lock);
    irq_enable();
}

#define spin_lock_irqsave(lock, flags) ({ \
    (flags) = spin_lock_irqsave(lock);    \
    })

#define assert_spin_locked(lock) MUST_HOLD_LOCK(lock)

#endif
