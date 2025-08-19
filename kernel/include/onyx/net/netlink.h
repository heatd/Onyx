/*
 * Copyright (c) 2025 Pedro Falcato
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
};

__BEGIN_CDECLS

void do_rtnetlink_send(struct netlink_sock *nlsk, struct packetbuf *pbf);

struct nlmsghdr *nl_put(struct packetbuf *pbf, pid_t pid, u32 seq, u16 type, u16 flags, u32 len);

__END_CDECLS

#endif
