/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#include <onyx/ref.h>
#include <onyx/scheduler.h>

void ref_init(struct ref *ref, unsigned long refcount, void (*releasefunc)(struct ref *))
{
    ref->refcount = refcount;
    ref->release = releasefunc;
}

bool ref_grab(struct ref *ref)
{
    __atomic_add_fetch(&ref->refcount, 1, __ATOMIC_ACQUIRE);

    return true;
}

void ref_release(struct ref *ref)
{
    if (__atomic_sub_fetch(&ref->refcount, 1, __ATOMIC_RELEASE) == 0)
    {
        if (ref->release)
            ref->release(ref);
    }
}

static bool refcount_dec_not_one(refcount_t *r)
{
    unsigned int new_val, val = READ_ONCE(r->refs);

    do
    {
        if (unlikely(val == 1))
            return false;
        new_val = val - 1;
    } while (!__atomic_compare_exchange_n(&r->refs, &val, new_val, true, __ATOMIC_RELEASE,
                                          __ATOMIC_RELAXED));
    return true;
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
bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock)
{
    if (refcount_dec_not_one(r))
        return false;

    mutex_lock(lock);
    if (!refcount_dec_and_test(r))
    {
        mutex_unlock(lock);
        return false;
    }

    return true;
}

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
bool refcount_dec_and_lock(refcount_t *r, struct spinlock *lock)
{
    if (refcount_dec_not_one(r))
        return false;

    spin_lock(lock);
    if (!refcount_dec_and_test(r))
    {
        spin_unlock(lock);
        return false;
    }

    return true;
}
