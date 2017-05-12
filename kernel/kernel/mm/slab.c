/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <kernel/compiler.h>
#include <kernel/vmm.h>
#include <kernel/slab.h>
#include <kernel/log.h>

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
	cache->addr = (void*)((uintptr_t)(cache + 2) & ~15);
	cache->size_bytes = size_obj;
	cache->num_objs = num_objs;
	cache->should_prefetch = sprefetch;
	slab_setup_caches(cache->addr, cache->size_bytes, cache->num_objs);
	INFO("slab","created cache %s\n", name);
	return cache;
}
void *slab_allocate(struct cache_info *cache)
{
	acquire_spinlock(&cache->lock);
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
		{
			release_spinlock(&cache->lock);
			return slab_allocate(cache->next);
		}
		else
		{
			/* If !cache->next, expand the cache */
			cache->next = slab_create(cache->name, cache->size_bytes, cache->num_objs, cache->should_prefetch);
			release_spinlock(&cache->lock);
			return slab_allocate(cache->next);
		}
	}
	ret->next = NULL;
	if(cache->should_prefetch) /* If we should prefetch objects from this cache, do so (this is just a neat little optimization) */
		prefetch(ret+1);
	release_spinlock(&cache->lock);
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
	if(!cache)
		return;
	acquire_spinlock(&cache->lock);
	
	/* Find the header */
	struct slab_header *header = (struct slab_header *)((char *) addr - sizeof(struct slab_header));
	header->next = slab_find_first_fit(cache);
	
	release_spinlock(&cache->lock);
}
