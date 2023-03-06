/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/fnv.h>
#include <onyx/wait.h>

#include "wait_impl.h"

#include <onyx/hashtable.hpp>

fnv_hash_t hash_wait(wait_token &wt)
{
    return fnv_hash(&wt.addr, sizeof(void *));
}

static cul::hashtable2<wait_token, 512, fnv_hash_t, hash_wait> ht;
static spinlock locks[512];

bool wait_token::complete() const
{
    return complete_(addr);
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
    auto hash = fnv_hash(&ptr, sizeof(void *));

    auto index = ht.get_hashtable_index(hash);

    scoped_lock<spinlock, true> g{locks[index]};

    auto lh = ht.get_hashtable(index);

    list_for_every_safe (lh)
    {
        auto w = container_of(l, wait_token, list_node);

        if (w->addr != ptr)
            continue;

        if (w->complete())
        {
            wait_queue_wake_all(&w->wq);
            woken++;
        }
    }

    return woken;
}

#if 0
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
#endif

int wait_for(void *ptr, bool (*complete)(void *), unsigned int flags, hrtime_t timeout)
{
    wait_token token{ptr, complete, flags};

    auto hash = hash_wait(token);

    auto index = ht.get_hashtable_index(hash);

    scoped_lock<spinlock, true> g{locks[index]};

    ht.add_element(token);

    g.unlock();

    int st;

    if (flags & WAIT_FOR_FOREVER)
        st = token.wait();
    else
        st = token.wait(timeout);

    g.lock();
    list_remove(&token.list_node);
    g.unlock();

    return st;
}
