/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_SPINLOCK_H
#define _ONYX_SPINLOCK_H

#include <assert.h>
#include <stdbool.h>

#include <onyx/arch_spinlock.h>
#include <onyx/atomic.h>
#include <onyx/compiler.h>
#include <onyx/irqflags.h>
#include <onyx/list.h>
#include <onyx/preempt.h>
#include <onyx/smp.h>
#include <onyx/utils.h>

#include <linux/lockdep_types.h>

// #include <onyx/lock_annotations.h>
#define __ACQUIRE(...)
#define __RELEASE(...)
#define __CAPABILITY(...)

struct __CAPABILITY("spinlock") spinlock
{
    arch_spinlock_t lock;
#ifdef CONFIG_SPINLOCK_DEBUG
    unsigned long holder;
#endif
#ifdef CONFIG_LOCKDEP
    struct lockdep_map dep_map;
#endif
};

#ifdef __cplusplus
extern "C"
{
#endif

void __spin_lock(struct spinlock *lock) __ACQUIRE(lock);
void __spin_unlock(struct spinlock *lock) __RELEASE(lock);
int spin_try_lock(struct spinlock *lock);

#ifdef CONFIG_LOCKDEP
void spinlock_init_lockdep(struct spinlock *lock, const char *name, struct lock_class_key *key);
#endif

#ifdef __cplusplus
}
#endif

CONSTEXPR static inline void __spinlock_init(struct spinlock *s)
{

#ifdef CONFIG_SPINLOCK_DEBUG
    s->holder = 0xDEADCAFEDEADCAFE;
#endif

    s->lock = ARCH_SPIN_LOCK_UNLOCKED;
}

#ifdef CONFIG_LOCKDEP
#define SPIN_DEP_MAP_INIT(lockname)        \
    .dep_map = {                           \
        .name = #lockname,                 \
        .wait_type_inner = LD_WAIT_CONFIG, \
    }
#define spinlock_init(lock)                         \
    do                                              \
    {                                               \
        static struct lock_class_key __key;         \
                                                    \
        __spinlock_init((lock));                    \
        spinlock_init_lockdep(lock, #lock, &__key); \
    } while (0)

#else
#define SPIN_DEP_MAP_INIT(lockname)
#define spinlock_init(lock) __spinlock_init(lock)
#endif

#define STATIC_SPINLOCK_INIT(name) {.lock = ARCH_SPIN_LOCK_UNLOCKED, SPIN_DEP_MAP_INIT(name)}

static inline FUNC_NO_DISCARD unsigned long spin_lock_irqsave(struct spinlock *lock) __ACQUIRE(lock)
{
    unsigned long flags = irq_save_and_disable();
    __spin_lock(lock);
    return flags;
}

static inline void spin_unlock_irqrestore(struct spinlock *lock, unsigned long old_flags)
    __RELEASE(lock)
{
    __spin_unlock(lock);
    irq_restore(old_flags);
}

static inline bool spin_lock_held(struct spinlock *lock)
{
    return READ_ONCE(lock->lock.lock) == get_cpu_nr() + 1;
}

static inline void spin_lock(struct spinlock *lock) __ACQUIRE(lock)
{
    sched_disable_preempt();

    __spin_lock(lock);
}

static inline void spin_unlock(struct spinlock *lock) __RELEASE(lock)
{
    __spin_unlock(lock);
    sched_enable_preempt();
}

#define MUST_HOLD_LOCK(lock) assert(spin_lock_held(lock) != false)

typedef struct spinlock spinlock_t;
#define spin_lock_init(s) spinlock_init(s)

#define __SPIN_LOCK_UNLOCKED(name) (spinlock_t) STATIC_SPINLOCK_INIT(name)
#define DEFINE_SPINLOCK(name)      struct spinlock name = __SPIN_LOCK_UNLOCKED(name)

#endif
