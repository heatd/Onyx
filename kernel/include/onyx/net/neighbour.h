/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_NEIGHBOUR_H
#define _ONYX_NET_NEIGHBOUR_H

#include <string.h>

#include <onyx/clock.h>
#include <onyx/fnv.h>
#include <onyx/list.h>
#include <onyx/net/inet_sock_addr.h>
#include <onyx/public/socket.h>
#include <onyx/timer.h>

#include <onyx/hashtable.hpp>
#include <onyx/memory.hpp>
#include <onyx/pair.hpp>
#include <onyx/slice.hpp>

#define NEIGHBOUR_VALIDITY_STATIC (~0UL)

void neighbour_revalidate(clockevent* ev);

class neighbour;

#define NEIGHBOUR_FLAG_UNINITIALISED (1 << 0)
#define NEIGHBOUR_FLAG_BADENTRY      (1 << 1)
#define NEIGHBOUR_FLAG_HAS_RESPONSE  (1 << 2)
#define NEIGHBOUR_FLAG_BROADCAST     (1 << 3)

class neighbour_table;

union neigh_proto_addr {
    in_addr in4addr;
    in6_addr in6addr;
};

class neighbour
{
protected:
    unsigned char* hwaddr_;
    unsigned int hwaddr_len_;
    int domain;
    struct clockevent expiry_timer;
    unsigned long validity_ms;

public:
    unsigned int flags;
    neighbour_table* table;

    union neigh_proto_addr proto_addr;

    explicit neighbour(int _domain, const neigh_proto_addr& addr)
        : hwaddr_{}, hwaddr_len_{}, domain{_domain}, flags{0}
    {
        if (_domain == AF_INET)
            proto_addr.in4addr.s_addr = addr.in4addr.s_addr;
        else if (_domain == AF_INET6)
            memcpy(&proto_addr.in6addr, &addr.in6addr, sizeof(in6_addr));
        else
            __builtin_unreachable();
    }

    ~neighbour()
    {
        delete[] hwaddr_;
    }

    cul::slice<unsigned char> hwaddr()
    {
        return {hwaddr_, hwaddr_len_};
    }

    void set_validity(unsigned long validity)
    {
        if (validity != NEIGHBOUR_VALIDITY_STATIC)
        {
            /* TODO: Check for overflows in validity maybe? */
            /* TODO: This API is clunky and we could and should have something like what userspace
             * has. */
            /* A better API would come in handy for TCP retransmissions */
            expiry_timer.deadline = clocksource_get_time() + validity * NS_PER_MS;
            expiry_timer.priv = this;
            expiry_timer.flags = CLOCKEVENT_FLAG_PULSE;
            expiry_timer.callback = neighbour_revalidate;
            timer_queue_clockevent(&expiry_timer);
        }

        validity_ms = validity;
    }

    void set_initialised()
    {
        flags &= ~NEIGHBOUR_FLAG_UNINITIALISED;
    }

    void set_error()
    {
        flags &= ~NEIGHBOUR_FLAG_BADENTRY;
    }

    int get_domain() const
    {
        return domain;
    }

    bool addr_equals(const neigh_proto_addr& addr)
    {
        if (domain == AF_INET)
            return proto_addr.in4addr.s_addr == addr.in4addr.s_addr;
        else if (domain == AF_INET6)
            return !memcmp(&proto_addr.in6addr, &addr.in6addr, sizeof(in6_addr));
        else
            __builtin_unreachable();
    }

    void set_hwaddr(cul::slice<unsigned char>& addr)
    {
        hwaddr_ = addr.data();
        hwaddr_len_ = addr.size_bytes();
    }
};

static inline fnv_hash_t hash_protoaddr(const neigh_proto_addr& addr, int domain)
{
    if (domain == AF_INET)
        return fnv_hash(&addr.in4addr, sizeof(addr.in4addr));
    else if (domain == AF_INET6)
        return fnv_hash(&addr.in6addr, sizeof(addr.in6addr));
    else
        __builtin_unreachable();
}

fnv_hash_t hash_neighbour(shared_ptr<neighbour>& neigh);

class neighbour_table
{
protected:
    cul::hashtable<shared_ptr<neighbour>, 32, fnv_hash_t, hash_neighbour> neighbour_cache;

    /* TODO: Is another lock type optimal here? Note that spinlocks have low overhead vs rwlocks
     * and lookups are *usually* quick.
     */
    spinlock lock;
    const int domain;

public:
    neighbour_table(int domain) : neighbour_cache{}, lock{}, domain{domain}
    {
        spinlock_init(&lock);
    }

    /**
     * @brief Add or get an existing neighbour entry
     *
     * @param addr the protocol address of the neighbour
     * @return cul::pair<shared_ptr<neighbour>, bool> a shared pointer to the neighbour + a bool
     * signaling if we created it or not.
     */
    cul::pair<shared_ptr<neighbour>, bool> add(const neigh_proto_addr& addr,
                                               bool only_lookup = false);
    void remove(neighbour* neigh);

    /**
     * @brief Clears cache entries
     *
     */
    void clear_cache();
};

#endif
