/*
 * Copyright (c) 2025 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_NET_NETLINK_H
#define _ONYX_NET_NETLINK_H

#include <onyx/net/socket.h>

#include <uapi/netlink.h>

struct netlink_sock
{
    struct socket sock;
    struct list_head buf_list;
    struct wait_queue wq;
    struct list_head bind_node;
    pid_t pid;
    unsigned int groups;
};

__BEGIN_CDECLS

struct nl_extack
{
    const char *msg;
};

void do_rtnetlink_send(struct netlink_sock *nlsk, struct packetbuf *pbf, struct nl_extack *extack);
int do_rtnetlink_bind(struct netlink_sock *nlsk, struct sockaddr_nl *nladdr);
void do_rtnetlink_unbind(struct netlink_sock *nlsk, u32 groups);

struct nlmsghdr *nl_put(struct packetbuf *pbf, pid_t pid, u32 seq, u16 type, u16 flags, u32 len);
int nl_done(struct packetbuf *pbf, pid_t pid, u32 seq, int err);
void netlink_ack(struct netlink_sock *nlsk, struct packetbuf *in_pbf, struct nlmsghdr *msg, int err,
                 struct nl_extack *extack);
void netlink_rcv_pbf(struct netlink_sock *nlsk, struct packetbuf *pbf);

#define NLA_UNKNOWN 0
#define NLA_U32     1

struct nla_attribute
{
    u32 len;
    u32 type;
};

static inline bool nla_ok(const struct nlattr *nla, int remaining)
{
    return remaining >= (int) sizeof(*nla) && nla->nla_len >= sizeof(*nla) &&
           nla->nla_len <= remaining;
}

static inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
    unsigned int totlen = NLA_ALIGN(nla->nla_len);

    *remaining -= totlen;
    return (struct nlattr *) ((char *) nla + totlen);
}

#define nla_for_each_attr(pos, head, len, rem) \
    for (pos = head, rem = len; nla_ok(pos, rem); pos = nla_next(pos, &(rem)))

int nla_parse_attr(struct nlattr **out, const struct nla_attribute *attr, size_t nr_attrs,
                   struct nlmsghdr *nlh, size_t header_size);

static inline void *nla_data(const struct nlattr *nla)
{
    return (char *) nla + NLA_HDRLEN;
}

static inline u32 nla_data_u32(const struct nlattr *nla)
{
    return *(u32 *) nla_data(nla);
}

__END_CDECLS

#endif
