/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_MUTEX_H
#define _ONYX_MUTEX_H

#include <string.h>

#include <onyx/assert.h>
#include <onyx/list.h>
#include <onyx/lock_annotations.h>
#include <onyx/spinlock.h>
#include <onyx/utils.h>

struct mutex;
CONSTEXPR static inline void mutex_init(struct mutex *mutex);

struct CAPABILITY("mutex") mutex
{
    struct spinlock llock;
    struct list_head thread_list;
    unsigned long counter;

#ifdef __cplusplus
    constexpr mutex() : llock{}, thread_list{}, counter{}
    {
        mutex_init(this);
    }

    mutex(const mutex &) = delete;
    mutex(mutex &&m) = delete;
    mutex &operator=(const mutex &) = delete;
    mutex &operator=(mutex &&) = delete;
#endif
};

#ifdef __cplusplus
#define DECLARE_MUTEX(name) mutex name

#else

#define DECLARE_MUTEX(name) struct mutex name = {.thread_list = LIST_HEAD_INIT(name.thread_list)};

#endif

#define MUTEX_INITIALIZER                          \
    {                                              \
        .thread_list = LIST_HEAD_INIT(thread_list) \
    }

CONSTEXPR static inline void mutex_init(struct mutex *mutex)
{
    spinlock_init(&mutex->llock);
    mutex->counter = 0;
    INIT_LIST_HEAD(&mutex->thread_list);
}

void mutex_lock(struct mutex *m) ACQUIRE(m);
void mutex_unlock(struct mutex *m) RELEASE(m);
int mutex_lock_interruptible(struct mutex *mutex) TRY_ACQUIRE(false, mutex);
bool mutex_holds_lock(struct mutex *m);
struct thread *mutex_owner(struct mutex *mtx);

#define MUST_HOLD_MUTEX(m) assert(mutex_holds_lock(m) == true)

#endif
