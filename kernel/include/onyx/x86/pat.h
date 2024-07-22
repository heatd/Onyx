/*
 * Copyright (c) 2018 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_X86_PAT_H
#define _ONYX_X86_PAT_H

#include <stdint.h>

#define PAT_UNCACHEABLE 0
#define PAT_WC          1
#define PAT_WT          4
#define PAT_WP          5
#define PAT_WB          6
#define PAT_UNCACHED    7

#define PAT_NR_ENTRIES 8

uint8_t cache_to_paging_bits(uint8_t type);
void pat_init(void);

#endif
