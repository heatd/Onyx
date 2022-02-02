/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <onyx/fnv.h>
#include <onyx/wait.h>

#include "wait_impl.h"

#include <onyx/hashtable.hpp>

fnv_hash_t hash_wait(wait_token &wt)
{
    return fnv_hash(wt.addr, sizeof(void *));
}

static cul::hashtable2<wait_token, 512, fnv_hash_t, hash_wait> ht;
static spinlock locks[512];

bool valid_size(uint8_t len)
{
    return len == 1 || len == 2 || len == 4 || len == 8;
}

bool wait_token::complete() const
{
    uint64_t val;

    switch (len)
    {
    case 1:
        val = *(uint8_t *)addr;
        break;
    case 2:
        val = *(uint16_t *)addr;
        break;
    case 4:
        val = *(uint32_t *)addr;
        break;
    case 8:
        val = *(uint64_t *)addr;
        break;
    default:
        __builtin_unreachable();
    }

    if (flags & WAIT_FOR_MATCHES_EVERYTHING)
        return (val & mask) == mask;
    else
        return val & mask;
}

int wait_token::wait()
{
    return wait_for_event(&wq, complete());
}

int wait_token::wait(hrtime_t timeout)
{
    return wait_for_event_timeout(&wq, complete(), timeout);
}

unsigned long wake_address(void *ptr)
{
    unsigned long woken = 0;
    auto hash = fnv_hash(ptr, sizeof(void *));

    auto index = ht.get_hashtable_index(hash);

    scoped_lock g{locks[index]};

    auto lh = ht.get_hashtable(index);

    list_for_every_safe (lh)
    {
        auto w = container_of(l, wait_token, list_node);

        if (w->addr != ptr)
            continue;

        if (w->complete())
        {
            list_remove(&w->list_node);
            wait_queue_wake_all(&w->wq);
            woken++;
        }
    }

    return woken;
}

int wait_for_mask(void *val, uint64_t mask, unsigned int flags, hrtime_t timeout)
{
    uint8_t len = flags & WAIT_FOR_SIZE_MASK;
    if (!len)
        len = sizeof(unsigned long);

    assert(valid_size(len));

    wait_token token{val, mask, flags, len};

    auto hash = hash_wait(token);

    auto index = ht.get_hashtable_index(hash);

    scoped_lock g{locks[index]};

    ht.add_element(token);

    g.unlock();

    int st;

    if (flags & WAIT_FOR_FOREVER)
        st = token.wait();
    else
        st = token.wait(timeout);

    return st;
}
