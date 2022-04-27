/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_PUBLIC_NETKERNEL_H
#define _ONYX_PUBLIC_NETKERNEL_H

#include <netinet/in.h>

struct netkernel_hdr
{
    unsigned int msg_type;
    unsigned int flags;
    unsigned long size;
    unsigned char data[0];
};

struct netkernel_error
{
    struct netkernel_hdr hdr;
    int error;
};

#define NETKERNEL_MSG_ERROR 0

#define NETKERNEL_MSG_ROUTE4_ADD 0x1000
#define NETKERNEL_MSG_ROUTE6_ADD 0x1010

#define NETKERNEL_MSG_IPV6_ADDRCFG 0x2000

#define NETKERNEL_PATH_MAX 109

#define NETKERNEL_MSG_NETIF_GET_NETIFS 0x1000

#define NETKERNEL_MSG_INET4_GET_ADDRS 0x1000

struct sockaddr_nk
{
    sa_family_t nk_family;
    /* netkernel addresses are expressed through a 109 character dot-separated path,
     * and are null terminated.
     */
    char path[NETKERNEL_PATH_MAX + 1];
};

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

struct netkernel_route4_add
{
    struct netkernel_hdr hdr;
    struct in_addr dest;
    struct in_addr gateway;
    struct in_addr mask;
    int metric;
    unsigned short flags;
    char iface[IF_NAMESIZE];
};

struct netkernel_route6_add
{
    struct netkernel_hdr hdr;
    struct in6_addr dest;
    struct in6_addr gateway;
    struct in6_addr mask;
    int metric;
    unsigned short flags;
    uint8_t hop_limit;
    char iface[IF_NAMESIZE];
};

struct netkernel_nif_interface
{
    unsigned int if_index;
    char if_name[IF_NAMESIZE];
    sockaddr if_hwaddr;
    sockaddr if_brdaddr;
    unsigned int if_mtu;
    // if.h documents the flags
    short if_flags;
};

struct netkernel_get_nifs_response
{
    struct netkernel_hdr hdr;
    // Number of interfaces that follow the header
    unsigned int nr_ifs;
};

#define ROUTE4_FLAG_GATEWAY (1 << 0)
#define ROUTE6_FLAG_GATEWAY ROUTE4_FLAG_GATEWAY

struct netkernel_ipv6_addrcfg
{
    struct netkernel_hdr hdr;
    struct in6_addr interface_id;
    char iface[IF_NAMESIZE];
};

#endif
