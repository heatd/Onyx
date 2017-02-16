/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <kernel/log.h>
#include <kernel/slab.h>
#include <kernel/fscache.h>

static struct fscache_hashtable
{
	struct fscache_hashtable *next;
	struct fscache_section *cache;
} cache_hashtable[FSCACHE_NR_HASHTABLE];
static struct cache_info *slab_cache = NULL;

static int hash_device(dev_t dev)
{
	return dev % FSCACHE_NR_HASHTABLE;
}
void fscache_initialize(void)
{
	/* Create a slab cache */
	slab_cache = slab_create("fscache", sizeof(struct fscache_section), 100, 0);
	if(!slab_cache)
	{
		ERROR("fscache", "No memory available for the caches.");
	}
}
void fscache_cache_sectors(char *sectors, block_device_t *dev, uint64_t lba, size_t count)
{
	printk("Caching!\n");
	struct fscache_section *s = slab_allocate(slab_cache);
	if(!s)
		return;
	s->dev = dev;
	s->lba = lba;
	s->count = count;
	s->data = malloc(count);
	if(!s->data)
	{
		slab_free(slab_cache, s);
		return;
	}
	memcpy(s->data, sectors, count);

	struct fscache_hashtable *h = &cache_hashtable[hash_device(dev->dev)];

	/* If it's the first cached sector in this hash */
	if(!h->cache)
	{
		h->cache = s;
		return;
	}
	/* Go to the end of the linked list */
	for(; h->next; h = h->next);

	/* Create a new node */
	h->next = malloc(sizeof(struct fscache_hashtable));
	if(!h->next)
	{
		free(s->data);
		slab_free(slab_cache, s);
		return;
	}
	h->next->cache = s;
	h->next->next = NULL;
}
inline uint64_t count2lba(size_t count)
{
	uint64_t lba = count / 512;
	if(count % 512)
		lba++;
	return lba;
}
void *fscache_try_to_find_block(uint64_t lba, block_device_t *dev, size_t count)
{
	if(!dev)
		return NULL;
	/* Calculate the hash */
	int hash = hash_device(dev->dev);

	/* Go through the fscache, looking for the data blocks in question */
	struct fscache_hashtable *h = &cache_hashtable[hash];

	for(; h->next; h = h->next)
	{
		if(h->cache->lba == lba && h->cache->dev == dev && h->cache->count >= count)
			return h->cache->data;
		if(h->cache->lba + count2lba(h->cache->count) > lba && h->cache->lba < lba)
			return h->cache->data + (h->cache->lba - lba) * 512;
	}

	return NULL;
}