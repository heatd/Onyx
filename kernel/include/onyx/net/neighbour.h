/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_NET_NEIGHBOUR_H
#define _ONYX_NET_NEIGHBOUR_H

#include <string.h>

#include <onyx/atomic.h>
#include <onyx/clock.h>
#include <onyx/fnv.h>
#include <onyx/list.h>
#include <onyx/net/inet_sock_addr.h>
#include <onyx/rcupdate.h>
#include <onyx/seqlock.h>
#include <onyx/timer.h>

#include <uapi/neighbour.h>
#include <uapi/socket.h>

#define NEIGHBOUR_VALIDITY_STATIC (~0UL)

void neighbour_revalidate(clockevent* ev);

#define NEIGHBOUR_FLAG_UNINITIALISED (1 << 0)
#define NEIGHBOUR_FLAG_BADENTRY      (1 << 1)
#define NEIGHBOUR_FLAG_HAS_RESPONSE  (1 << 2)
#define NEIGHBOUR_FLAG_BROADCAST     (1 << 3)

struct neighbour_table;

union neigh_proto_addr {
    struct in_addr in4addr;
    struct in6_addr in6addr;
};

struct neigh_ops
{
    int (*resolve)(struct neighbour* neigh, struct netif* nif);
    int (*output)(struct neighbour* neigh, struct packetbuf* pbf, struct netif* nif);
};

void neigh_timer(struct clockevent* ev);

struct neighbour
{
    unsigned int refcount;
    unsigned int hwaddr_len;
    union {
        unsigned char hwaddr[16];
        struct rcu_head rcu_head;
    };

    unsigned int retry;
    int domain;
    struct clockevent expiry_timer;
    hrtime_t confirmed;
    hrtime_t delay_probe;
    unsigned long validity_ms;
    struct netif* netif;
    u16 flags;
    u16 state;
    struct neighbour_table* table;
    union neigh_proto_addr proto_addr;
    const struct neigh_ops* neigh_ops;
    struct list_head list_node;
    seqlock_t neigh_seqlock;
    struct list_head packet_queue;

    explicit neighbour(int _domain, const neigh_proto_addr& addr, struct netif* netif)
        : refcount{1}, hwaddr_len{}, retry{}, domain{_domain}, confirmed{0}, delay_probe{0},
          netif{netif}, flags{NEIGHBOUR_FLAG_UNINITIALISED}, state{0}, neigh_ops{}
    {
        if (_domain == AF_INET)
            proto_addr.in4addr.s_addr = addr.in4addr.s_addr;
        else if (_domain == AF_INET6)
            memcpy(&proto_addr.in6addr, &addr.in6addr, sizeof(in6_addr));
        else
            __builtin_unreachable();
        clockevent_init(&expiry_timer, neigh_timer, 0);
        seqlock_init(&neigh_seqlock);
        INIT_LIST_HEAD(&packet_queue);
    }

    ~neighbour() = default;

    void set_validity(unsigned long validity)
    {
        if (validity != NEIGHBOUR_VALIDITY_STATIC)
        {
            /* TODO: Check for overflows in validity maybe? */
            /* TODO: This API is clunky and we could and should have something like what userspace
             * has. */
            /* A better API would come in handy for TCP retransmissions */
            clockevent_init(&expiry_timer, neighbour_revalidate, CLOCKEVENT_FLAG_PULSE);
            expiry_timer.deadline = clocksource_get_time() + validity * NS_PER_MS;
            expiry_timer.priv = this;
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
};

static inline bool neigh_needs_resolve(struct neighbour* neigh)
{
    /* Only bother trying to resolve neighbours if they're not yet resolved, or if there are no
     * requests pending. */
    return !(READ_ONCE(neigh->state) &
             (NUD_PROBE | NUD_REACHABLE | NUD_INCOMPLETE | NUD_STALE | NUD_DELAY));
}

void neigh_start_resolve(struct neighbour* neigh, struct netif* nif);
void neigh_output_queued(struct neighbour* neigh);
void __neigh_complete_lookup(struct neighbour* neigh, const void* hwaddr, unsigned int len);

static inline void neigh_complete_lookup(struct neighbour* neigh, const void* hwaddr,
                                         unsigned int len)
{
    write_seqlock(&neigh->neigh_seqlock);
    __neigh_complete_lookup(neigh, hwaddr, len);
    write_sequnlock(&neigh->neigh_seqlock);
}

static inline fnv_hash_t hash_protoaddr(const neigh_proto_addr& addr, int domain)
{
    if (domain == AF_INET)
        return fnv_hash(&addr.in4addr, sizeof(addr.in4addr));
    else if (domain == AF_INET6)
        return fnv_hash(&addr.in6addr, sizeof(addr.in6addr));
    else
        __builtin_unreachable();
}

#define NEIGH_TAB_NR_CHAINS 32

struct neighbour_table
{
    struct list_head neigh_tab[NEIGH_TAB_NR_CHAINS];
    struct spinlock lock __align_cache;

    /* read-only/read-mostly members (on a separate cacheline) */
    const int domain __align_cache;
    const hrtime_t reachable_time{30000 * NS_PER_MS};
    const hrtime_t retrans_time{1000 * NS_PER_MS};
    const hrtime_t delay_first_probe_time{5 * NS_PER_SEC};
    const unsigned int max_retrans{3};

    neighbour_table(int domain) : lock{}, domain{domain}
    {
        spinlock_init(&lock);
        for (int i = 0; i < NEIGH_TAB_NR_CHAINS; i++)
            INIT_LIST_HEAD(&neigh_tab[i]);
    }
};

typedef unsigned int gfp_t;

struct neighbour* neigh_find(struct neighbour_table* table, const union neigh_proto_addr* addr,
                             struct netif* netif);
struct neighbour* neigh_add(struct neighbour_table* table, const union neigh_proto_addr* addr,
                            struct netif* netif, gfp_t gfp, const struct neigh_ops* ops,
                            int* added);
void neigh_remove(struct neighbour_table* table, struct neighbour* neigh);
void neigh_clear(struct neighbour_table* table);
void neigh_free(struct neighbour* neigh);

static inline void neigh_get(struct neighbour* neigh)
{
    __atomic_add_fetch(&neigh->refcount, 1, __ATOMIC_RELAXED);
}

static inline void neigh_put(struct neighbour* neigh)
{
    if (__atomic_sub_fetch(&neigh->refcount, 1, __ATOMIC_RELAXED) == 0)
        neigh_free(neigh);
}

static inline bool neigh_get_careful(struct neighbour* neigh)
{
    unsigned int ref = READ_ONCE(neigh->refcount);
    unsigned int old;

    do
    {
        if (unlikely(ref == 0))
            return false;
        old = ref;
    } while ((ref = cmpxchg(&neigh->refcount, ref, ref + 1)) != old);

    return true;
}

int neigh_output(struct neighbour* neigh, struct packetbuf* pbf, struct netif* nif);

static inline void neigh_set_ops(struct neighbour* neigh, struct neigh_ops* ops)
{
    WRITE_ONCE(neigh->neigh_ops, ops);
}

int do_getneigh(struct netlink_sock* nlsk, struct packetbuf* pbf, struct nlmsghdr* nlh_,
                struct rtgenmsg* rth);

void __neigh_mark_reachable(struct neighbour* neigh);

#define NEIGH_CONFIRMED_SLACK (100 * NS_PER_MS)

/**
 * @brief Confirm a neighbour on a packet input path
 * Only supposed to be used by protocols with two-way communication, where receiving a packet means
 * that our forward-path is alive. Such an example is TCP, but _not_ UDP.
 *
 * @param neigh Neighbour to confirm
 */
static void neigh_confirm_input(struct neighbour* neigh)
{
    hrtime_t time = clocksource_get_time();

    /* This is best-effort anyway - no need to touch it too often. If it was soon enough, skip the
     * confirmation. Otherwise, cache ping-ponging happens. */
    if (READ_ONCE(neigh->confirmed) + NEIGH_CONFIRMED_SLACK < time)
        WRITE_ONCE(neigh->confirmed, time);
}
#endif
