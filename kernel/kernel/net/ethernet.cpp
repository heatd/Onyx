/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/byteswap.h>
#include <onyx/crc32.h>
#include <onyx/net/arp.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/ip.h>
#include <onyx/net/network.h>
#include <onyx/vm.h>

#include <pci/pci.h>

eth_dll_ops eth_ops;

static const uint16_t eth_proto_table[] = {PROTO_IPV4, PROTO_IPV6, PROTO_ARP};

auto tx_proto_to_eth_proto(tx_protocol proto)
{
    return eth_proto_table[(int) proto];
}

int eth_dll_ops::setup_header(packetbuf *buf, tx_type type, tx_protocol proto, netif *nif,
                              const void *dst_hw)
{
    auto hdr = buf->link_header ? (eth_header *) buf->link_header
                                : (struct eth_header *) buf->push_header(sizeof(struct eth_header));

    memset(hdr, 0, sizeof(struct eth_header));

    buf->link_header = (unsigned char *) hdr;

    hdr->ethertype = htons(tx_proto_to_eth_proto(proto));
    if (type == tx_type::unicast)
        memcpy(&hdr->mac_dest, dst_hw, ETH_ALEN);
    else if (type == tx_type::broadcast)
        memset(hdr->mac_dest, 0xff, ETH_ALEN);
    else if (type == tx_type::multicast)
    {
        if (proto == tx_protocol::ipv6)
        {
            /* IPv6 addresses have a multicast mac of 33-33 and then the rest is filled with
             * the lower 32 bits of the IPv6 address.
             */
            const in6_addr *addr = (const in6_addr *) dst_hw;
            hdr->mac_dest[0] = 0x33;
            hdr->mac_dest[1] = 0x33;

            for (unsigned int i = 0; i < 4; i++)
            {
                hdr->mac_dest[2 + i] = addr->s6_addr[12 + i];
            }
        }
        else if (proto == tx_protocol::ipv4)
        {
            /* IPv4 addresses have a multicast mac of 01-00-5E- and then the rest is
             * filled with the lower 23-bits of the IPv4 address - because of that,
             * we need to mask out the first bit of the first byte.
             */

            const unsigned char *addr = (const unsigned char *) dst_hw + 1;
            hdr->mac_dest[0] = 01;
            hdr->mac_dest[1] = 00;
            hdr->mac_dest[2] = 0x5e;
            memcpy(&hdr->mac_dest[3], addr, 3);
            hdr->mac_dest[3] &= 0x7f;
        }
    }

    memcpy(&hdr->mac_source, &nif->mac_address, ETH_ALEN);

    return 0;
}

extern "C" int eth_dll_ops::rx_packet(netif *netif, packetbuf *buf)
{
    struct eth_header *hdr = (struct eth_header *) buf->data;

    /* Bad packet */
    if (sizeof(struct eth_header) >= buf->length())
        return -EIO;

    buf->data += sizeof(eth_header);

    auto ethertype = ntohs(hdr->ethertype);

    switch (ethertype)
    {
        case PROTO_IPV4:
            return ip::v4::handle_packet(netif, buf);
        case PROTO_IPV6:
            return ip::v6::handle_packet(netif, buf);
        case PROTO_ARP:
            return arp_handle_packet(netif, buf);
    }

    return 0;
}
