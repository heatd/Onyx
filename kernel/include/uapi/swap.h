/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _UAPI_SWAP_H
#define _UAPI_SWAP_H

#include <onyx/types.h>

#define SWAP_VERSION_CURRENT 0
/* MAGIC = "ONYXSWAP", backwards on big endian */
#define SWAP_MAGIC           0x5041575358594E4F

/* Used if we go over BADBLOCKS, or if BADBLOCKS themselves are bad */
#define SWP_FLAG_BAD (1 << 0)

#define SWP_RESERVED_BADBLOCKS_PAGES 8

typedef __u64 __swap_block_t;

struct swap_super
{
    __u64 swp_magic;
    __u32 swp_version;
    __u32 swp_pagesize;
    __swap_block_t swp_nr_pages;
    __u32 swp_flags;
    __u32 swp_nr_badblocks;
    __u8 swp_uuid[16];
};

#define MIN_SWAP_SIZE_PAGES (SWP_RESERVED_BADBLOCKS_PAGES + 1)

#endif
