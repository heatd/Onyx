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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <kernel/compiler.h>
#include <kernel/vmm.h>
#include <kernel/slab.h>

// NOT WORKING: NEEDS FIXES
void slab_setup_caches(void *addr, size_t size_obj, size_t num_objs)
{
	struct slab_header *hd = addr;
	//printf("------------------------SLAB INFO-------------------------\n\t\tSize in bytes of each object (%u)\n\t\tNumber of objects (%u)\n----------------------------------------------------------\n", size_obj, num_objs);
	for(size_t i = 0; i < num_objs; i++)
	{
		hd->next = (struct slab_header *)((char*)&hd->data + size_obj);
		hd = hd->next;
	}
}
struct cache_info *slab_create(const char *name, size_t size_obj, size_t num_objs, int sprefetch)
{
	struct cache_info *cache = vmalloc(vmm_align_size_to_pages((size_obj * num_objs) +
sizeof(struct cache_info) + num_objs * sizeof(struct slab_header)), VM_TYPE_REGULAR, VM_WRITE | VM_NOEXEC | VM_GLOBAL);
	cache->name = name;
	cache->addr = cache+1;
	cache->size_bytes = size_obj;
	cache->num_objs = num_objs;
	cache->should_prefetch = sprefetch;
	slab_setup_caches(cache->addr, cache->size_bytes, cache->num_objs);
	printf("Created cache %s\n", name);
	return cache;
}
void *slab_allocate(struct cache_info *cache)
{
	struct slab_header *hd = (struct slab_header *)(cache+1);
	_Bool found = false;
	struct slab_header *ret = NULL;
	for(size_t i = 0; i < cache->num_objs; i++)
	{
		if(hd->next != NULL)
		{
			ret = hd;
			found = true;
			break;
		}
		hd = (struct slab_header *)((char*) &hd->data + cache->size_bytes);
	}
	if(!found)
	{
		/* If there's a chained cache, try to allocate from it */
		if(cache->next)
			return slab_allocate(cache->next);
		else
		{
			/* If !cache->next, expand the cache */
			cache->next = slab_create(cache->name, cache->size_bytes, cache->num_objs, cache->should_prefetch);
			return slab_allocate(cache->next);
		}
	}
	ret->next = NULL;
	if(cache->should_prefetch) /* If we should prefetch objects from this cache, do so (this is just a neat little optimization) */
		prefetch(ret+1);
	return ret+1;
}
struct slab_header *slab_find_first_fit(struct cache_info *cache)
{
	struct slab_header *hd = cache->addr;
	for(size_t i = 0; i < cache->num_objs; i++)
	{
		if(hd->next != NULL)
		{
			return hd;
		}
		hd = (struct slab_header *)((char*) &hd->data + cache->size_bytes);
	}
	return NULL;
}
void slab_free(struct cache_info *cache, void *addr)
{
	if(!addr)
		return;
	struct slab_header *header = (struct slab_header *)((char *) addr - cache->size_bytes);
	header->next = slab_find_first_fit(cache);
	if(header->next == NULL) header->next = header; // Just so we don't waste an object
}
