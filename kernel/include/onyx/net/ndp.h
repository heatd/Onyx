/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_NET_NDP_H
#define _ONYX_NET_NDP_H

#include <onyx/net/netif.h>

struct neighbour *ndp_resolve(const in6_addr &ip, struct netif *netif);
int ndp_handle_packet(netif *netif, packetbuf *buf);

#endif
