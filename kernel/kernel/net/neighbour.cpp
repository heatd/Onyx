/*
 * Copyright (c) 2020 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/mm/slab.h>
#include <onyx/net/neighbour.h>
#include <onyx/net/rtnetlink.h>
#include <onyx/new.h>
#include <onyx/packetbuf.h>
#include <onyx/panic.h>
#include <onyx/rculist.h>
#include <onyx/scoped_lock.h>

#include <uapi/netlink.h>

void neighbour_revalidate(clockevent* ev)
{
    // TODO: Implement
    ev->deadline = clocksource_get_time() + NS_PER_SEC * 60 * 20;
}

struct neighbour* neigh_find(struct neighbour_table* table, const union neigh_proto_addr* addr,
                             struct netif* netif)
{
    struct neighbour* neigh;
    u32 hash = hash_protoaddr(*addr, table->domain);
    u32 index = hash & (NEIGH_TAB_NR_CHAINS - 1);

    rcu_read_lock();

    list_for_each_entry_rcu (neigh, &table->neigh_tab[index], list_node)
    {
        if (neigh->addr_equals(*addr) && neigh->netif == netif)
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
    timer_cancel_event(&neigh->expiry_timer);
    kfree_rcu(neigh, rcu_head);
}

struct neighbour* neigh_add(struct neighbour_table* table, const union neigh_proto_addr* addr,
                            struct netif* netif, gfp_t gfp, const struct neigh_ops* ops, int* added)
{
    struct neighbour *neigh, *n2;
    u32 hash, index;
    *added = 1;

    neigh = neigh_find(table, addr, netif);
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

    new (neigh) neighbour(table->domain, *addr, netif);
    neigh->neigh_ops = ops;
    neigh->table = table;
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

void __neigh_mark_reachable(struct neighbour* neigh)
{
    neigh->state = NUD_REACHABLE;
    neigh->confirmed = clocksource_get_time();
    timer_mod(&neigh->expiry_timer, neigh->confirmed + neigh->table->reachable_time);
}

void __neigh_complete_lookup(struct neighbour* neigh, const void* hwaddr, unsigned int len)
{
    memcpy(neigh->hwaddr, hwaddr, len);
    neigh->hwaddr_len = len;
    __neigh_mark_reachable(neigh);
    neigh_output_queued(neigh);
}

void neigh_timer(struct clockevent* ev)
{
    struct neighbour* neigh = container_of(ev, struct neighbour, expiry_timer);
    const struct neighbour_table* tab = neigh->table;
    hrtime_t now = clocksource_get_time();

    write_seqlock(&neigh->neigh_seqlock);
    if (neigh->state == NUD_INCOMPLETE)
    {
        if (neigh->retry++ > tab->max_retrans)
        {
            neigh->state = NUD_FAILED;
            goto out;
        }

        neigh->neigh_ops->resolve(neigh, neigh->netif);
        if (neigh->state == NUD_REACHABLE)
            goto out;
        neigh->expiry_timer.deadline = now + tab->retrans_time;
        timer_queue_clockevent(&neigh->expiry_timer);
    }
    else if (neigh->state == NUD_REACHABLE)
    {
        if (neigh->confirmed + tab->reachable_time <= now)
        {
            /* More than ReachableTime milliseconds elapsed, transition to STALE. */
            neigh->state = NUD_STALE;
        }
        else
        {
            neigh->expiry_timer.deadline = neigh->confirmed + tab->reachable_time;
            timer_queue_clockevent(&neigh->expiry_timer);
        }
    }
    else if (neigh->state == NUD_DELAY)
    {
        if (neigh->delay_probe + tab->delay_first_probe_time <= now)
        {
            /* Go into PROBE and start probing */
            neigh->state = NUD_PROBE;
            neigh->retry = 0;
            neigh->neigh_ops->resolve(neigh, neigh->netif);
            neigh->expiry_timer.deadline = now + tab->retrans_time;
            timer_queue_clockevent(&neigh->expiry_timer);
        }
        else if (neigh->confirmed + tab->reachable_time > now)
        {
            /* Confirmed by someone, switch to reachable */
            neigh->state = NUD_REACHABLE;
            neigh->expiry_timer.deadline = neigh->confirmed + tab->reachable_time;
            timer_queue_clockevent(&neigh->expiry_timer);
        }
    }
    else if (neigh->state == NUD_PROBE)
    {
        if (neigh->retry++ > tab->max_retrans)
        {
            neigh->state = NUD_FAILED;
            goto out;
        }
        neigh->neigh_ops->resolve(neigh, neigh->netif);
        neigh->expiry_timer.deadline = now + tab->retrans_time;
        timer_queue_clockevent(&neigh->expiry_timer);
    }

out:
    write_sequnlock(&neigh->neigh_seqlock);
}

void neigh_start_resolve(struct neighbour* neigh, struct netif* nif)
{
    write_seqlock(&neigh->neigh_seqlock);

    neigh->retry = 0;
    if (neigh_needs_resolve(neigh))
    {
        WARN_ON_ONCE(neigh->state != 0);
        neigh->neigh_ops->resolve(neigh, nif);
        neigh->state = NUD_INCOMPLETE;
        neigh->expiry_timer.deadline = clocksource_get_time() + NS_PER_SEC;
        timer_queue_clockevent(&neigh->expiry_timer);
    }

    write_sequnlock(&neigh->neigh_seqlock);
}

int neigh_output(struct neighbour* neigh, struct packetbuf* pbf, struct netif* nif)
{
    CHECK(pbf->route.nif);
    unsigned int state = READ_ONCE(neigh->state);
    if (likely(state & NUD_REACHABLE))
        return neigh->neigh_ops->output(neigh, pbf, nif);
    /* Slow path - check the neighbour's state, try to resolve it and queue our own packet. Per
     * RFC1122: The link layer SHOULD save (rather than discard) at least one (the latest)
     * packet of each set of packets destined to the same unresolved IP address, and transmit
     * the saved packet when the address has been resolved.
     */

    spin_lock(&neigh->neigh_seqlock.lock);
    state = neigh->state;
    if (state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY))
    {
        /* Just send it. */
        if (state == NUD_STALE)
        {
            /* Neighbour is stale. Move it to probe and start the delay probe. Reachability
             * confirmation will bring it back to REACHABLE. */
            neigh->state = NUD_DELAY;
            neigh->delay_probe = clocksource_get_time();
            timer_mod(&neigh->expiry_timer,
                      neigh->delay_probe + neigh->table->delay_first_probe_time);
        }
        spin_unlock(&neigh->neigh_seqlock.lock);
        return neigh->neigh_ops->output(neigh, pbf, nif);
    }

    /* Probe pending (or will be). Append our packet and leave. */
    list_add_tail(&pbf->list_node, &neigh->packet_queue);
    pbf_get(pbf);
    spin_unlock(&neigh->neigh_seqlock.lock);

    if (state & (NUD_PROBE | NUD_INCOMPLETE))
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
        WARN_ON_ONCE(pbf->route.nif != neigh->netif);
        neigh->neigh_ops->output(neigh, pbf, pbf->route.nif);
        pbf_put_ref(pbf);
    }
}

extern struct neighbour_table arp_table, ndp_table;

static int table_getneigh(struct neighbour_table* table, struct netlink_sock* nlsk,
                          struct packetbuf* pbf, struct nlmsghdr* nlh_, struct rtgenmsg* rth)
{
    /* Only supports v4/v6 for now */
    const u32 proto_addr_len = table->domain == AF_INET ? 4 : 16;
    struct neighbour* neigh;
    struct nlmsghdr* nlh;
    struct ndmsg* msg;
    int err = 0;

    rcu_read_lock();
    for (int i = 0; i < NEIGH_TAB_NR_CHAINS; i++)
    {
        list_for_each_entry_rcu (neigh, &table->neigh_tab[i], list_node)
        {
            err = -EMSGSIZE;
            nlh = nl_put(pbf, nlsk->pid, nlh_->nlmsg_seq, RTM_NEWNEIGH, NLM_F_MULTI, sizeof(*msg));
            if (!nlh)
                break;

            msg = (struct ndmsg*) NLMSG_DATA(nlh);
            msg->ndm_family = table->domain;
            msg->ndm_flags = 0;
            msg->ndm_ifindex = neigh->netif->if_id;
            msg->ndm_pad1 = msg->ndm_pad2 = 0;
            msg->ndm_state = neigh->state;
            msg->ndm_type = RTN_UNICAST;

            if (nla_put(pbf, NDA_DST, proto_addr_len, &neigh->proto_addr))
                break;
            if (neigh->hwaddr_len > 0 && nla_put(pbf, NDA_LLADDR, neigh->hwaddr_len, neigh->hwaddr))
                break;
            nlh->nlmsg_len = pbf->tail - (unsigned char*) nlh;
            err = 0;
        }
    }
    rcu_read_unlock();
    return err;
}

int do_getneigh(struct netlink_sock* nlsk, struct packetbuf* pbf, struct nlmsghdr* nlh_,
                struct rtgenmsg* rth)
{
    int err = 0;

    switch (rth->rtgen_family)
    {
        case AF_UNSPEC:
        case AF_INET:
            err = table_getneigh(&arp_table, nlsk, pbf, nlh_, rth);
            if (err || rth->rtgen_family != AF_UNSPEC)
                break;
            [[__fallthrough__]];
        case AF_INET6:
            err = table_getneigh(&ndp_table, nlsk, pbf, nlh_, rth);
            break;
        default:
            err = -EOPNOTSUPP;
    }
    return err;
}
