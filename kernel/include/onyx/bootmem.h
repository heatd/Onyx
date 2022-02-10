/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_BOOTMEM_H
#define _ONYX_BOOTMEM_H

#include <stddef.h>
#include <stdint.h>

#define BOOTMEM_FLAG_LOW_MEM (1 << 0)

void *alloc_boot_page(size_t nr_pgs, long flags);

void bootmem_reserve(unsigned long start, size_t size);
void bootmem_add_range(unsigned long start, size_t size);

void for_every_phys_region(void (*callback)(unsigned long start, size_t size));

#endif
