/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_NET_INET_PROTO_FAMILY_H
#define _ONYX_NET_INET_PROTO_FAMILY_H

#include <onyx/net/inet_route.h>

struct netif;

struct inet_socket;

/**
 * @brief Implements IPv4/v6 specific functions.
 *        Note that v6's functions redirect to v4 code when they detect the socket is in v4 mode.
 */
struct inet_proto_family
{
    int (*bind)(struct sockaddr *addr, socklen_t len, struct inet_socket *sock);
    int (*bind_any)(struct inet_socket *sock);
    expected<inet_route, int> (*route)(const inet_sock_address &from, const inet_sock_address &to,
                                       int domain);
    void (*unbind)(struct inet_socket *sock);
#ifdef __cplusplus
    static bool add_socket(inet_socket *sock);
#endif
};

struct ip_option
{
    uint8_t option;
    uint16_t length;
    /* TODO: This is not optimal nor correct and we're doing it for simplicity purposes only */
    unsigned char buf[255];
};

#endif
