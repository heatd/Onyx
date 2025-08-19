/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/net/rtnetlink.h>

enum rtnl_kinds
{
    RTNL_KIND_NEW,
    RTNL_KIND_DEL,
    RTNL_KIND_GET,
    RTNL_KIND_SET
};

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
    pr_warn("rtnl send %u\n", type);
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
        return -EINVAL;

    new_pbf = pbf_alloc_sk(GFP_KERNEL, &nlsk->sock, PAGE_SIZE);
    if (!new_pbf)
        return -ENOMEM;
    err = handler(nlsk, new_pbf, nlh, rth);
    if (err < 0)
    {
        pbf_free(new_pbf);
        pr_warn("err %d\n", err);
        return err;
    }

    list_add_tail(&new_pbf->list_node, &nlsk->buf_list);
    wait_queue_wake_all(&nlsk->wq);
    pr_warn("done yay\n");
    return err;
}

void do_rtnetlink_send(struct netlink_sock *nlsk, struct packetbuf *pbf)
{
    struct nlmsghdr *msg;

    while ((msg = pbf_pull(pbf, sizeof(struct nlmsghdr))) != NULL)
    {
        if (msg->nlmsg_len < sizeof(struct nlmsghdr) ||
            msg->nlmsg_len - sizeof(struct nlmsghdr) > pbf_length(pbf))
            break;

        if (msg->nlmsg_type < NLMSG_MIN_TYPE || !(msg->nlmsg_flags & NLM_F_REQUEST))
            goto ack;

        do_handle_rtnl(nlsk, pbf, msg);
    ack:
        /* TODO */
        pbf_pull(pbf, msg->nlmsg_len - sizeof(*msg));
    }
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
