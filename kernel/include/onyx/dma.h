/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_DMA_H
#define _ONYX_DMA_H

#include <stddef.h>
#include <stdint.h>

struct phys_range
{
	uintptr_t addr;
	size_t size;
};

struct phys_ranges
{
	struct phys_range **ranges;
	size_t nr_ranges;
};

/* 
 * dma_get_ranges() - Get a list of physical ranges from the underlying vbuf
 * of size buf_size, each range having a max size of max_range.
*/

int dma_get_ranges(const void *vbuf, size_t buf_size, size_t max_range,
	struct phys_ranges *ranges);

void dma_destroy_ranges(struct phys_ranges *ranges);

#endif
