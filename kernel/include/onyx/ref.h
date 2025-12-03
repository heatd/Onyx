/*
 * Copyright (c) 2018 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_REF_H
#define _ONYX_REF_H

#include <stdbool.h>

#include <onyx/atomic.h>
#include <onyx/compiler.h>
#include <onyx/mutex.h>
#include <onyx/spinlock.h>

struct ref
{
    unsigned long refcount;
    void (*release)(struct ref *ref);
};

__BEGIN_CDECLS

void ref_init(struct ref *ref, unsigned long refcount, void (*releasefunc)(struct ref *));
bool ref_grab(struct ref *ref);
void ref_release(struct ref *ref);

typedef struct __refcount_t
{
    unsigned int refs;
} refcount_t;

#define REFCOUNT_INIT(refcount) ((refcount_t) {.refs = (refcount)})

static inline void refcount_set(refcount_t *r, unsigned int refs)
{
    WRITE_ONCE(r->refs, refs);
}

static inline void refcount_inc(refcount_t *r)
{
    __atomic_add_fetch(&r->refs, 1, __ATOMIC_RELAXED);
}

static inline bool refcount_dec_and_test(refcount_t *r)
{
    return !__atomic_sub_fetch(&r->refs, 1, __ATOMIC_RELAXED);
}

static inline bool refcount_inc_not_zero(refcount_t *r)
{
    unsigned int old, expected;

    old = READ_ONCE(r->refs);
    do
    {
        expected = old;
        if (unlikely(!old))
            return false;
        old = cmpxchg(&r->refs, expected, expected + 1);
    } while (unlikely(old != expected));

    return true;
}

static inline unsigned int refcount_read(const refcount_t *r)
{
    return __atomic_load_n(&r->refs, __ATOMIC_RELAXED);
}

/**
 * refcount_dec_and_mutex_lock - return holding mutex if able to decrement
 *                               refcount to 0
 * @r: the refcount
 * @lock: the mutex to be locked
 *
 * Similar to atomic_dec_and_mutex_lock(), it will WARN on underflow and fail
 * to decrement when saturated at REFCOUNT_SATURATED.
 *
 * Provides release memory ordering, such that prior loads and stores are done
 * before, and provides a control dependency such that free() must come after.
 * See the comment on top.
 *
 * Return: true and hold mutex if able to decrement refcount to 0, false
 *         otherwise
 */
bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock);

/**
 * refcount_dec_and_lock - return holding spinlock if able to decrement
 *                         refcount to 0
 * @r: the refcount
 * @lock: the spinlock to be locked
 *
 * Similar to atomic_dec_and_lock(), it will WARN on underflow and fail to
 * decrement when saturated at REFCOUNT_SATURATED.
 *
 * Provides release memory ordering, such that prior loads and stores are done
 * before, and provides a control dependency such that free() must come after.
 * See the comment on top.
 *
 * Return: true and hold spinlock if able to decrement refcount to 0, false
 *         otherwise
 */
bool refcount_dec_and_lock(refcount_t *r, struct spinlock *lock);

__END_CDECLS

#endif
