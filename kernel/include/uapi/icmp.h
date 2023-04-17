/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_ICMP_H
#define _UAPI_ICMP_H

#define ICMP_ADD_FILTER 0x10000

#define ICMP_FILTER_TYPE_UNSPEC (-1U)
#define ICMP_FILTER_CODE_UNSPEC (-1U)

struct icmp_filter
{
    unsigned int type;
    unsigned int code;
};

/* Export the definition to user-space */

#ifndef SOL_ICMP

#define SOL_ICMP 800

#endif

#ifndef SOL_ICMPV6

#define SOL_ICMPV6 58

#endif

#endif
