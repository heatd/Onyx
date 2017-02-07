/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_FSCACHE_H
#define _KERNEL_FSCACHE_H

#include <stdint.h>
#include <stddef.h>

#include <kernel/block.h>

#define FSCACHE_NR_HASHTABLE 512

struct fscache_section
{
	uint64_t lba;
	block_device_t *dev;
	size_t nr_sectors;
	unsigned char *data;
};
void fscache_initialize(void);
void fscache_cache_sectors(char *sectors, block_device_t *dev, uint64_t lba, size_t nr_sectors);
void *fscache_try_to_find_block(uint64_t lba, block_device_t *dev, size_t nr_sectors);

#endif