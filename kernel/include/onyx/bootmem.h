/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_BOOTMEM_H
#define _ONYX_BOOTMEM_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/compiler.h>

#define BOOTMEM_FLAG_HIGH_MEM (1 << 0)

__BEGIN_CDECLS

void *alloc_boot_page(size_t nr_pgs, long flags);

void bootmem_reserve(unsigned long start, size_t size);
void bootmem_add_range(unsigned long start, size_t size);

void for_every_phys_region(void (*callback)(unsigned long start, size_t size));
__END_CDECLS

#endif
