/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_NET_DLL_H
#define _ONYX_NET_DLL_H

struct packetbuf;
struct netif;

enum class tx_type
{
    unicast = 0,
    broadcast,
    multicast
};

enum class tx_protocol
{
    ipv4 = 0,
    ipv6,
    arp
};

class data_link_layer_ops
{
public:
    virtual int setup_header(packetbuf *buf, tx_type type, tx_protocol proto, netif *nif,
                             const void *dst_hw) = 0;
    virtual int rx_packet(netif *nif, packetbuf *buf) = 0;
};

#endif
