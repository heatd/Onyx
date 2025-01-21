/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_REF_H
#define _ONYX_REF_H

#include <stdbool.h>

#include <onyx/atomic.h>
#include <onyx/compiler.h>

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

#define REFCOUNT_INIT(refcount) ((refcount_t){.refs = (refcount)})

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

__END_CDECLS

#endif
