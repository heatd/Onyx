/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_SLAB_H
#define _KERNEL_SLAB_H
#include <stdint.h>
#include <stddef.h>
struct cache_info
{
	const char *name;
	void *addr;
	size_t size_bytes;
	size_t num_objs;
	size_t should_prefetch; /* Using size_t here so we're sure this aligns nicely */
	struct cache_info *next;
};
struct slab_header
{
	struct slab_header *next;
	char data[0];
}__attribute__((packed));
struct cache_info *slab_create(const char *name, size_t size_obj, size_t num_objs, int sprefetch);
void *slab_allocate(struct cache_info *cache);
void slab_free(struct cache_info *cache, void *addr);


#endif
