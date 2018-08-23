/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>
#include <stdio.h>
#include <onyx/dma.h>
#include <onyx/vm.h>

#define min(x, y)	(x < y ? x : y)

static void *expand_array(void *old, size_t new_size)
{
	return realloc(old, new_size);
}

static bool try_to_merge(uintptr_t buf, size_t size, size_t max_size,
	struct phys_ranges *ranges)
{
	/* Try to merge the new range with an old range by checking the last
	 * range. If r->addr + r->size == buf, this means the two areas are
	 * contiguous. But, since this is DMA code, we need to check if an
	 * area is too big and the hardware doesn't support such a size, so
	 * in reality the condition is (r->addr + r->size == buf) &&
	 * r->size + size <= max_size.
	*/
	if(!ranges->nr_ranges)
		return false;

	size_t last = ranges->nr_ranges - 1;

	struct phys_range *r = ranges->ranges[last];

	/* Perfect! Merge the two entries and return success */
	if(r->addr + r->size == buf && r->size + size <= max_size)
	{
		r->size += size;
		return true;
	}

	return false;
}

int __dma_add_range(uintptr_t virtual_buf, size_t size, size_t max_size,
	struct phys_ranges *ranges)
{
	uintptr_t phys_buf = (uintptr_t) virtual2phys((void *) virtual_buf);

	if(try_to_merge(phys_buf, size, max_size, ranges) == true)
		return 0;

	ranges->nr_ranges++;
	size_t idx = ranges->nr_ranges - 1;

	void *n = expand_array(ranges->ranges, ranges->nr_ranges *
			       sizeof(struct phys_range *));

	if(!n)
		return -1;
	
	ranges->ranges = (struct phys_range **) n;

	ranges->ranges[idx] = malloc(sizeof(struct phys_range));

	if(!ranges->ranges[idx])
		return -1;

	ranges->ranges[idx]->addr = phys_buf;
	ranges->ranges[idx]->size = size;

	return 0;
}

int dma_get_ranges(void *vbuf, size_t buf_size, size_t max_range,
	struct phys_ranges *ranges)
{
	uintptr_t buf = (uintptr_t) vbuf;
	ranges->nr_ranges = 0;
	ranges->ranges = NULL;

	while(buf_size != 0)
	{
		/* Handle non-page-aligned buffers by doing it a page at a time*/
		size_t buf_page_size = PAGE_SIZE - (buf & (PAGE_SIZE-1));
		size_t s = min(buf_page_size, buf_size);
		s = min(s, max_range);

		if(__dma_add_range(buf, s, max_range, ranges) < 0)
		{
			if(ranges->ranges)
				free(ranges->ranges);
			return -1;
		}

		buf_size -= s;
		buf += s;
	}

	return 0;
	
}

void dma_destroy_ranges(struct phys_ranges *ranges)
{
	for(size_t i = 0; i < ranges->nr_ranges; i++)
		free(ranges->ranges[i]);
	free(ranges->ranges);
}