/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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

static int hash_device(dev_t dev)
{
	return dev % FSCACHE_NR_HASHTABLE;
}
void fscache_cache_sectors(char *sectors, block_device_t *dev, uint64_t lba, size_t count)
{
	struct fscache_section *s = malloc(sizeof(struct fscache_section));
	if(!s)
		return;
	s->dev = dev;
	s->lba = lba;
	s->count = count;
	s->data = malloc(count);
	if(!s->data)
	{
		free(s);
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
		free(s);
		return;
	}
	h->next->cache = s;
	h->next->next = NULL;
}
static inline uint64_t count2lba(size_t count)
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
