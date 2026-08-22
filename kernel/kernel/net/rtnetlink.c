/*
 * Copyright (c) 2025 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/net/rtnetlink.h>

struct rtnl_group_member
{
    struct netlink_sock *nlsk;
    struct list_head list;
};

enum rtnl_kinds
{
    RTNL_KIND_NEW,
    RTNL_KIND_DEL,
    RTNL_KIND_GET,
    RTNL_KIND_SET
};

static DEFINE_SPINLOCK(rtnl_group_lock);
static struct list_head rtnl_groups[RTNLGRP_MAX];

#define RTNL_KIND_MASK 3

static inline enum rtnl_kinds rtnl_msgtype_kind(int msgtype)
{
    return msgtype & RTNL_KIND_MASK;
}

static rtnl_handler_t handlers[RTM_NR_MSGTYPES];

void rtnl_register(int family, rtnl_handler_t handler)
{
    handlers[family - RTM_BASE] = handler;
}

static int do_handle_rtnl(struct netlink_sock *nlsk, struct packetbuf *pbf, struct nlmsghdr *nlh)
{
    struct packetbuf *new_pbf;
    rtnl_handler_t handler;
    struct rtgenmsg *rth;
    int type, err;

    type = nlh->nlmsg_type;
    if (type > RTM_MAX)
        return -EOPNOTSUPP;

    if (nlh->nlmsg_len - sizeof(*nlh) < sizeof(*rth))
    {
        /* We must have at least one byte of payload, for rtgenmsg */
        return -EINVAL;
    }

    rth = (struct rtgenmsg *) (nlh + 1);

    handler = handlers[nlh->nlmsg_type - RTM_BASE];
    if (!handler)
        return -EOPNOTSUPP;

    new_pbf = pbf_alloc_sk(GFP_KERNEL, &nlsk->sock, PAGE_SIZE);
    if (!new_pbf)
        return -ENOMEM;
    err = handler(nlsk, new_pbf, nlh, rth);
    if (err < 0)
    {
        pbf_free(new_pbf);
        return err;
    }

    list_add_tail(&new_pbf->list_node, &nlsk->buf_list);
    wait_queue_wake_all(&nlsk->wq);
    return err;
}

void do_rtnetlink_send(struct netlink_sock *nlsk, struct packetbuf *pbf, struct nl_extack *extack)
{
    struct nlmsghdr *msg;
    int err;

    while ((msg = pbf_pull(pbf, sizeof(struct nlmsghdr))) != NULL)
    {
        if (msg->nlmsg_len < sizeof(struct nlmsghdr) ||
            msg->nlmsg_len - sizeof(struct nlmsghdr) > pbf_length(pbf))
            break;

        err = 0;
        if (msg->nlmsg_type < NLMSG_MIN_TYPE || !(msg->nlmsg_flags & NLM_F_REQUEST))
            goto ack;

        err = do_handle_rtnl(nlsk, pbf, msg);
    ack:
        if (msg->nlmsg_flags & NLM_F_ACK || err)
            netlink_ack(nlsk, pbf, msg, err, extack);
        pbf_pull(pbf, msg->nlmsg_len - sizeof(*msg));
    }
}

struct packetbuf *rtnl_start_broadcast(u32 group)
{
    struct packetbuf *pbf;

    pbf = pbf_alloc_rx(GFP_KERNEL, PAGE_SIZE);
    /* Unclear if there's something interesting to do with group here. Perhaps we could pre-allocate
     * the clones? */
    return pbf;
}

void rtnl_end_broadcast(struct packetbuf *pbf, u32 group)
{
    struct rtnl_group_member *memb;
    struct netlink_sock *nlsk;
    struct packetbuf *clone;

    if (nl_done(pbf, 0, 0, 0))
        goto out;

    spin_lock(&rtnl_group_lock);

    list_for_each_entry (memb, &rtnl_groups[group - 1], list)
    {
        nlsk = memb->nlsk;
        clone = packetbuf_clone(pbf);
        if (!clone)
        {
            /* Crap. Set socket error and continue. */
            WRITE_ONCE(nlsk->sock.sock_err, -ENOMEM);
            continue;
        }

        hybrid_lock_bh(&nlsk->sock.socket_lock);
        if (!hybrid_is_ours(&nlsk->sock.socket_lock))
            list_add_tail(&clone->list_node, &nlsk->sock.socket_backlog);
        else
            netlink_rcv_pbf(nlsk, clone);
        hybrid_unlock_bh(&nlsk->sock.socket_lock);
    }
    spin_unlock(&rtnl_group_lock);
out:
    pbf_put_ref(pbf);
}

int nla_put(struct packetbuf *pbf, u16 type, u16 len, const void *data)
{
    struct rtattr *attr;
    int size;

    size = sizeof(*attr) + len;
    attr = pbf_put(pbf, NLA_ALIGN(size));
    if (!attr)
        return -EMSGSIZE;

    attr->rta_len = size;
    attr->rta_type = type;
    if (NLA_ALIGN(size) > size)
        memset(RTA_DATA(attr) + size, 0, NLA_ALIGN(size) - size);
    memcpy(RTA_DATA(attr), data, len);
    return 0;
}

int nla_put_str(struct packetbuf *pbf, u16 type, const char *str)
{
    size_t len = strlen(str) + 1;

    return nla_put(pbf, type, len, str);
}

int nla_put_u32(struct packetbuf *pbf, u16 type, u32 data)
{
    return nla_put(pbf, type, sizeof(u32), &data);
}

static void free_rtnl_sub(u32 group, struct netlink_sock *nlsk)
{
    struct rtnl_group_member *memb;

    list_for_each_entry (memb, &rtnl_groups[group], list)
    {
        if (memb->nlsk == nlsk)
        {
            list_remove(&memb->list);
            kfree(memb);
            return;
        }
    }
    /* This is not supposed to happen.... */
    WARN_ON_ONCE(1);
}

static void __do_rtnetlink_unbind(struct netlink_sock *nlsk, u32 groups)
{
    unsigned int group = 0;
    while (groups > 0)
    {
        if (groups & 1)
            free_rtnl_sub(group, nlsk);

        group++;
        groups >>= 1;
    }
}

void do_rtnetlink_unbind(struct netlink_sock *nlsk, u32 groups)
{
    spin_lock(&rtnl_group_lock);
    __do_rtnetlink_unbind(nlsk, groups);
    spin_unlock(&rtnl_group_lock);
}

int do_rtnetlink_bind(struct netlink_sock *nlsk, struct sockaddr_nl *nladdr)
{
    u32 groups = nladdr->nl_groups;
    struct rtnl_group_member *memb;
    unsigned int group = 0, done = 0;

    spin_lock(&rtnl_group_lock);
    while (groups > 0)
    {
        if (groups & 1)
        {
            memb = kmalloc(sizeof(*memb), GFP_NOWAIT);
            if (!memb)
                goto undo;
            memb->nlsk = nlsk;
            list_add_tail(&memb->list, &rtnl_groups[group]);
            done |= (1U << group);
        }

        group++;
        groups >>= 1;
    }
    spin_unlock(&rtnl_group_lock);
    return 0;
undo:
    __do_rtnetlink_unbind(nlsk, done);
    spin_unlock(&rtnl_group_lock);
    return -ENOMEM;
}

static __init void rtnetlink_init(void)
{
    for (int i = 0; i < RTNLGRP_MAX; i++)
        INIT_LIST_HEAD(&rtnl_groups[i]);
}
