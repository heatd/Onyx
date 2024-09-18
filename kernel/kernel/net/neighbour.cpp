/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/mm/slab.h>
#include <onyx/net/neighbour.h>
#include <onyx/new.h>
#include <onyx/packetbuf.h>
#include <onyx/panic.h>
#include <onyx/rculist.h>
#include <onyx/scoped_lock.h>

void neighbour_revalidate(clockevent* ev)
{
    // TODO: Implement
    ev->deadline = clocksource_get_time() + NS_PER_SEC * 60 * 20;
}

struct neighbour* neigh_find(struct neighbour_table* table, const union neigh_proto_addr* addr)
{
    struct neighbour* neigh;
    u32 hash = hash_protoaddr(*addr, table->domain);
    u32 index = hash & (NEIGH_TAB_NR_CHAINS - 1);

    rcu_read_lock();

    list_for_each_entry_rcu (neigh, &table->neigh_tab[index], list_node)
    {
        if (neigh->addr_equals(*addr))
        {
            if (neigh_get_careful(neigh))
                goto out;
        }
    }

    neigh = NULL;
out:
    rcu_read_unlock();
    return neigh;
}

void neigh_free(struct neighbour* neigh)
{
    kfree_rcu(neigh, rcu_head);
}

struct neighbour* neigh_add(struct neighbour_table* table, const union neigh_proto_addr* addr,
                            gfp_t gfp, const struct neigh_ops* ops, int* added)
{
    struct neighbour *neigh, *n2;
    u32 hash, index;
    *added = 1;

    neigh = neigh_find(table, addr);
    if (neigh)
    {
        *added = 0;
        return neigh;
    }

    neigh = (struct neighbour*) kmalloc(sizeof(*neigh), gfp);
    if (!neigh)
        return NULL;

    hash = hash_protoaddr(*addr, table->domain);
    index = hash & (NEIGH_TAB_NR_CHAINS - 1);

    new (neigh) neighbour(table->domain, *addr);
    neigh->neigh_ops = ops;
    spin_lock(&table->lock);

    /* No need for _rcu since we hold the lock */
    list_for_each_entry (n2, &table->neigh_tab[index], list_node)
    {
        if (n2->addr_equals(*addr))
        {
            /* We can skip neigh_get_careful here since we hold the spinlock */
            neigh_get(n2);
            spin_unlock(&table->lock);
            kfree(neigh);
            *added = 0;
            return n2;
        }
    }

    /* Not found, add */
    neigh_get(neigh);
    list_add_tail_rcu(&neigh->list_node, &table->neigh_tab[index]);

    spin_unlock(&table->lock);
    return neigh;
}

void neigh_remove(struct neighbour_table* table, struct neighbour* neigh)
{
    spin_lock(&table->lock);
    list_remove_rcu(&neigh->list_node);
    spin_unlock(&table->lock);
    neigh_put(neigh);
}

static void neigh_clear_chain(struct neighbour_table* table, u32 i)
{
    struct neighbour* n;
    list_for_each_entry (n, &table->neigh_tab[i], list_node)
    {
        list_remove(&n->list_node);
        neigh_put(n);
    }
}

void neigh_clear(struct neighbour_table* table)
{
    spin_lock(&table->lock);

    for (u32 i = 0; i < NEIGH_TAB_NR_CHAINS; i++)
        neigh_clear_chain(table, i);

    spin_unlock(&table->lock);
}

void neigh_start_resolve(struct neighbour* neigh, struct netif* nif)
{
    write_seqlock(&neigh->neigh_seqlock);

    if (neigh_needs_resolve(neigh))
        neigh->neigh_ops->resolve(neigh, nif);

    if (neigh->flags & NUD_STALE)
    {
        neigh->flags &= ~NUD_STALE;
        neigh->flags |= NUD_PROBE;
    }
    else
    {
        neigh->flags |= NUD_INCOMPLETE;
    }

    write_sequnlock(&neigh->neigh_seqlock);
}

int neigh_output(struct neighbour* neigh, struct packetbuf* pbf, struct netif* nif)
{
    CHECK(pbf->route.nif);
    unsigned int flags = READ_ONCE(neigh->flags);
    if (likely(flags & NUD_REACHABLE))
        return neigh->neigh_ops->output(neigh, pbf, nif);
    /* Slow path - check the neighbour's state, try to resolve it and queue our own packet. Per
     * RFC1122: The link layer SHOULD save (rather than discard) at least one (the latest)
     * packet of each set of packets destined to the same unresolved IP address, and transmit
     * the saved packet when the address has been resolved.
     */

    if (flags & NUD_REACHABLE)
    {
        /* Just send it */
        return neigh->neigh_ops->output(neigh, pbf, nif);
    }

    /* Probe pending (or will be). Append our packet and leave. This requires the lock. */
    spin_lock(&neigh->neigh_seqlock.lock);
    list_add_tail(&pbf->list_node, &neigh->packet_queue);
    pbf_get(pbf);
    spin_unlock(&neigh->neigh_seqlock.lock);

    if (flags & (NUD_PROBE | NUD_INCOMPLETE))
        return 0;

    /* Not reachable nor probe nor incomplete - we don't have a probe. Start a resolve. */
    neigh_start_resolve(neigh, nif);
    return 0;
}

void neigh_output_queued(struct neighbour* neigh)
{
    struct packetbuf *pbf, *next;
    list_for_each_entry_safe (pbf, next, &neigh->packet_queue, list_node)
    {
        CHECK(pbf->route.nif != NULL);
        list_remove(&pbf->list_node);
        neigh->neigh_ops->output(neigh, pbf, pbf->route.nif);
        pbf_put_ref(pbf);
    }
}
