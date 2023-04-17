/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_MEMSTAT_H
#define _UAPI_MEMSTAT_H

#include <onyx/types.h>

struct memstat
{
    __usize total_pages;
    __usize allocated_pages;
    __usize page_cache_pages;
    __usize kernel_heap_pages;
};

#endif
