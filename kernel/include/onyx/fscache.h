/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_FSCACHE_H
#define _KERNEL_FSCACHE_H

#include <stdint.h>
#include <stddef.h>

#include <onyx/block.h>

#define FSCACHE_NR_HASHTABLE 512

struct fscache_section
{
	uint64_t lba;
	struct blockdev *dev;
	size_t count;
	unsigned char *data;
};
void fscache_cache_sectors(char *sectors, struct blockdev *dev, uint64_t lba, size_t count);
void *fscache_try_to_find_block(uint64_t lba, struct blockdev *dev, size_t count);

#endif
