/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 license.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _LINUX_ATOMIC_H
#define _LINUX_ATOMIC_H

#include <linux/types.h>
#include <onyx/atomic.h>
#include <linux/compiler.h>

struct mutex;

static inline int atomic_read(atomic_t *v)
{
    return READ_ONCE(v->counter);
}

static inline s64 atomic64_read(atomic64_t *v)
{
    return READ_ONCE(v->counter);
}

#define xchg(ptr, v) __atomic_exchange_n(ptr, v, __ATOMIC_SEQ_CST)
#define try_cmpxchg(ptr, old, new) __atomic_compare_exchange_n(ptr, old, new, true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)

static __always_inline void atomic64_add(s64 inc, atomic64_t *v)
{
    __atomic_add_fetch(&v->counter, inc, __ATOMIC_SEQ_CST);
}

static __always_inline int atomic_add_return(int inc, atomic_t *v)
{
    return __atomic_add_fetch(&v->counter, inc, __ATOMIC_SEQ_CST);
}

static __always_inline s64 atomic64_inc_return(atomic64_t *v)
{
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static __always_inline s64 atomic64_fetch_inc(atomic64_t *v)
{
    return __atomic_fetch_add(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static __always_inline int atomic_fetch_inc(atomic_t *v)
{
    return __atomic_fetch_add(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static __always_inline void atomic_inc(atomic_t *v)
{
    __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static __always_inline void atomic_dec(atomic_t *v)
{
    __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static __always_inline bool atomic_dec_and_test(atomic_t *v)
{
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST) == 0;
}

static __always_inline bool atomic_add_unless(atomic_t *v, int a, int u)
{
    int old = atomic_read(v);

    do
    {
        if (old == u)
            return false;
    } while (!try_cmpxchg(&v->counter, &old, old + a));

    return true;
}

int atomic_dec_and_mutex_lock(atomic_t *v, struct mutex *lock);

#endif
