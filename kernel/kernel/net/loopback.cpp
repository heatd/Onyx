/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/byteswap.h>
#include <onyx/init.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/netif.h>
#include <onyx/net/network.h>
#include <onyx/packetbuf.h>

/*
 * The loopback device uses a global packet queue (pqueue) protected by a single spinlock
 * (pqueue_lock). Note that this obviously doesn't scale. It may be a good idea to get a percpu
 * thing, or maybe some other scheme.
 */
static spinlock pqueue_lock = STATIC_SPINLOCK_INIT;
static list_head pqueue = LIST_HEAD_INIT(pqueue);

/**
 * @brief Send a packet through the loopback device
 *
 * @param buf pbuf to send
 * @param nif Our nif (allocated in loopback_init)
 * @return 0 on success, negative error codes
 */
int loopback_send_packet(packetbuf *buf, netif *nif)
{
    // We need to clone the original buf so we can pass it
    // down the stack again.
    auto newbuf = packetbuf_clone(buf);
    if (!newbuf)
        return -ENOMEM;

    // Append the packet to the pqueue (see above) and signal RX

    spin_lock(&pqueue_lock);

    list_add_tail(&newbuf->list_node, &pqueue);

    spin_unlock(&pqueue_lock);
    netif_signal_rx(nif);

    return 0;
}

/**
 * @brief Dispatch pending RX packets
 *
 * @param nif Our nif (allocated in loopback_init)
 * @return 0 on success, negative error codes
 */
int loopback_pollrx(netif *nif)
{
    // We need to hold the lock around list accesses (pqueue).
    DEFINE_LIST(queue);
    spin_lock(&pqueue_lock);
    list_splice_tail_init(&pqueue, &queue);
    spin_unlock(&pqueue_lock);

    while (!list_is_empty(&queue))
    {
        auto pbuf = container_of(list_first_element(&queue), packetbuf, list_node);
        list_remove(&pbuf->list_node);
        netif_process_pbuf(nif, pbuf);
        pbuf->unref();
    }

    return 0;
}

/**
 * @brief Initialize the loopback device
 * To think about: is there any advantage in being able to have multiple?
 * (apart from modularity and maybe testing)
 *
 */
void loopback_init()
{
    netif *n = new netif{};
    n->flags = NETIF_LINKUP | NETIF_LOOPBACK;
    n->name = "lo";
    n->mtu = UINT16_MAX;
    n->local_ip.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    n->sendpacket = loopback_send_packet;
    n->poll_rx = loopback_pollrx;
    n->rx_end = [](netif *nif) {}; // rx_end does nothing for us, as we do not have interrupts.
    n->dll_ops = &eth_ops;

    netif_register_if(n);

    if_inet6_addr addr;
    addr.address = in6addr_loopback;
    addr.flags = INET6_ADDR_GLOBAL;
    addr.prefix_len = 0;

    assert(netif_add_v6_address(n, addr) == 0);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(loopback_init);
