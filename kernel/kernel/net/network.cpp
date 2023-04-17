/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <assert.h>
#include <errno.h>
#include <uapi/fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <onyx/compiler.h>
#include <onyx/dpc.h>
#include <onyx/file.h>
#include <onyx/log.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/icmp.h>
#include <onyx/net/ip.h>
#include <onyx/net/network.h>
#include <onyx/net/udp.h>
#include <onyx/packetbuf.h>

#include <onyx/mm/pool.hpp>

static const char *hostname = "";

const char *network_gethostname()
{
    return hostname;
}

void network_sethostname(const char *name)
{
    if (strcmp((char *) hostname, ""))
        free((void *) hostname);
    hostname = name;
}

memory_pool<network_args, MEMORY_POOL_USABLE_ON_IRQ> pool;

void network_do_dispatch(void *__args)
{
    network_args *args = reinterpret_cast<network_args *>(__args);
    // network_handle_packet(args->buffer, args->size, args->netif);
    pool.free(args);
}

void network_dispatch_receive(uint8_t *packet, uint16_t len, struct netif *netif)
{
    network_args *args = reinterpret_cast<network_args *>(pool.allocate());
    if (!args)
    {
        ERROR("net", "Could not receive packet: Out of memory inside IRQ\n");
        return;
    }

    args->buffer = packet;
    args->size = len;
    args->netif = netif;

    struct dpc_work work = {};
    work.funcptr = network_do_dispatch;
    work.context = args;
    dpc_schedule_work(&work, DPC_PRIORITY_HIGH);
}
