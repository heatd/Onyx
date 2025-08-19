/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_NET_RTNETLINK_H
#define _ONYX_NET_RTNETLINK_H

#include <onyx/net/netlink.h>
#include <onyx/net/socket.h>

#include <uapi/rtnetlink.h>

typedef int (*rtnl_handler_t)(struct netlink_sock *nlsk, struct packetbuf *pbf,
                              struct nlmsghdr *nlh, struct rtgenmsg *rth);

__BEGIN_CDECLS
void rtnl_register(int family, rtnl_handler_t handler);
int nla_put(struct packetbuf *pbf, u16 type, u16 len, const void *data);
int nla_put_str(struct packetbuf *pbf, u16 type, const char *str);
int nla_put_u32(struct packetbuf *pbf, u16 type, u32 data);

__END_CDECLS
#endif
