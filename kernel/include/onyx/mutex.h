/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_MUTEX_H
#define _ONYX_MUTEX_H

#include <string.h>

#include <onyx/assert.h>
#include <onyx/list.h>
#include <onyx/lock_annotations.h>
#include <onyx/spinlock.h>
#include <onyx/utils.h>

#include <linux/lockdep_types.h>

struct mutex;
CONSTEXPR static inline void __mutex_init(struct mutex *mutex);

struct CAPABILITY("mutex") mutex
{
    struct spinlock llock;
    struct list_head waiters;
    unsigned long counter;

#ifdef CONFIG_LOCKDEP
    struct lockdep_map dep_map;
#endif

#ifdef __cplusplus
    constexpr mutex(int a) : llock{}, waiters{}, counter{}
    {
        __mutex_init(this);
#ifdef CONFIG_LOCKDEP
        if (a == 0)
        {
            dep_map.wait_type_inner = LD_WAIT_SLEEP;
            dep_map.name = "lockname";
        }
#endif
    }

    mutex() = delete;
    mutex(const mutex &) = delete;
    mutex(mutex &&m) = delete;
    mutex &operator=(const mutex &) = delete;
    mutex &operator=(mutex &&) = delete;
#endif
};

#ifdef CONFIG_LOCKDEP
#define __DEP_MAP_MUTEX_INITIALIZER(lockname) \
    , .dep_map = {                            \
          .name = #lockname,                  \
          .wait_type_inner = LD_WAIT_SLEEP,   \
    }
#else
#define __DEP_MAP_MUTEX_INITIALIZER(lockname)
#endif

#ifdef __cplusplus
#define DECLARE_MUTEX(name) mutex name{0}
#else
#define DECLARE_MUTEX(name) \
    struct mutex name = {.waiters = LIST_HEAD_INIT(name.waiters) __DEP_MAP_MUTEX_INITIALIZER(name)};
#endif

#define MUTEX_INITIALIZER(name) \
    {.waiters = LIST_HEAD_INIT((name).waiters) __DEP_MAP_MUTEX_INITIALIZER(name)}

CONSTEXPR static inline void __mutex_init(struct mutex *mutex)
{
    spinlock_init(&mutex->llock);
    mutex->counter = 0;
    INIT_LIST_HEAD(&mutex->waiters);
}

__BEGIN_CDECLS

void mutex_lock(struct mutex *m) ACQUIRE(m);
void mutex_unlock(struct mutex *m) RELEASE(m);
int mutex_lock_interruptible(struct mutex *mutex) TRY_ACQUIRE(0, mutex);
bool mutex_holds_lock(struct mutex *m);
struct thread *mutex_owner(struct mutex *mtx);
bool mutex_trylock(struct mutex *lock) TRY_ACQUIRE(true, lock);
void mutex_lockdep_init(struct mutex *mutex, const char *name, struct lock_class_key *key);

#ifndef CONFIG_LOCKDEP
#define mutex_init(mutex)                  __mutex_init(mutex)
#define mutex_init_novalidate(mutex)       mutex_init(mutex)
#define mutex_lock_nested(mutex, subclass) mutex_lock(mutex)
#else
#define mutex_init(mutex)                            \
    do                                               \
    {                                                \
        static struct lock_class_key __key;          \
                                                     \
        __mutex_init((mutex));                       \
        mutex_lockdep_init((mutex), #mutex, &__key); \
    } while (0)

void mutex_lock_nested(struct mutex *m, int subclass);

void mutex_lockdep_novalidate(struct mutex *mutex, const char *name);

#define mutex_init_novalidate(mutex)               \
    do                                             \
    {                                              \
        __mutex_init((mutex));                     \
        mutex_lockdep_novalidate((mutex), #mutex); \
    } while (0)
#endif

__END_CDECLS

#define MUST_HOLD_MUTEX(m) assert(mutex_holds_lock(m) == true)

#endif
