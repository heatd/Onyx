/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _UAPI_NET_TYPES_H
#define _UAPI_NET_TYPES_H

typedef unsigned int __socklen_t;
typedef unsigned short __sa_family_t;

#ifdef __is_onyx_kernel
typedef __socklen_t socklen_t;
typedef __sa_family_t sa_family_t;
#endif

struct sockaddr
{
    __sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_storage
{
    __sa_family_t ss_family;
    char __ss_padding[128 - sizeof(long) - sizeof(__sa_family_t)];
    unsigned long __ss_align;
};

#endif
