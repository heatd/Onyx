/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include <onyx/compiler.h>
#include <onyx/vm.h>
#include <onyx/slab.h>
#include <onyx/log.h>

static slab_cache_t *first_slab;
static slab_cache_t *last_slab;

int slab_setup_bufctls(struct slab *slab, slab_cache_t *cache)
{
	bufctl_t *bufctl = NULL;
	for(size_t off = 0; off < slab->size; off += cache->size)
	{
		void *buf = (void*)((char*) slab->buf + off); 
		if(!bufctl)
		{
			/* Construct the bufctl */
			slab->bufctls = malloc(sizeof(bufctl_t));
			/* TODO: Handle this case */
			if(!slab->bufctls)
				return errno = ENOMEM, -1;
			slab->bufctls->prev = NULL;
			slab->bufctls->next = NULL;
			slab->bufctls->inuse = BUFCTL_FREE;
			slab->bufctls->buf = buf;
			bufctl = slab->bufctls;
		}
		else
		{
			bufctl_t *bctl = malloc(sizeof(bufctl_t));
			/* TODO: Handle this case */
			if(!bctl)
				return errno = ENOMEM, -1;
			bufctl->next = bctl;
			bctl->prev = bufctl;
			bctl->next = NULL;
			bctl->inuse = BUFCTL_FREE;
			bctl->buf = buf;
			bufctl = bctl;
		}
		/* Call the constructor */
		if(cache->ctor)
			cache->ctor(buf);
	}
	return 0;
}

struct slab *slab_create_slab(size_t size_obj, slab_cache_t *cache)
{
	size_t slab_size;
	if(size_obj < PAGE_SIZE / 8)
	{
		slab_size = PAGE_SIZE;
	}
	else
	{
		slab_size = 30 * size_obj;
	}

	struct slab *slab = malloc(sizeof(struct slab));
	if(!slab)
	{
		return errno = ENOMEM, NULL;
	}
	memset(slab, 0, sizeof(struct slab));

	void *buffer = vmalloc(vm_align_size_to_pages(slab_size),
		VM_TYPE_REGULAR, VM_NOEXEC  | VM_WRITE);
	if(!buffer)
	{
		free(slab);
		return errno = ENOMEM, NULL;
	}

	slab->size = slab_size;
	slab->buf = buffer;
	if(slab_setup_bufctls(slab, cache) < 0)
	{
		vfree(buffer, vm_align_size_to_pages(slab_size));
		free(slab);
		return errno = ENOMEM, NULL;
	}

	return slab;
}

slab_cache_t *slab_create(const char *name, size_t size_obj, size_t alignment, int flags, void (*ctor)(void*), void (*dtor)(void*))
{
	slab_cache_t *cache = malloc(sizeof(slab_cache_t));
	if(!cache)
		return errno = ENOMEM, NULL;
	memset(cache, 0, sizeof(slab_cache_t));
	/* TODO: Detect the correct cache alignment */
	size_t obj_alignment = alignment == 0 ? 16 : alignment;
	size_obj = ((size_obj + obj_alignment) & -obj_alignment);
	
	cache->name = name;
	cache->size = size_obj;
	cache->ctor = ctor;
	cache->dtor = dtor;
	cache->alignment = obj_alignment;
	cache->flags = flags;
	cache->slab_list = slab_create_slab(size_obj, cache);
	if(!cache->slab_list)
	{
		free(cache);
		return errno = ENOMEM, NULL;
	}

	if(!first_slab)
	{
		first_slab = cache;
		last_slab = cache;
	}
	else
	{
		cache->prev = last_slab;
		last_slab->next = cache;
	}

	return cache;
}

void *slab_allocate_from_slab(struct slab *slab)
{
	bufctl_t *bufctl = slab->bufctls;
	while(bufctl)
	{
		if(bufctl->inuse == BUFCTL_FREE)
		{
			/* Mark the bufctl as in use and return the object */
			bufctl->inuse = BUFCTL_INUSE;
			return bufctl->buf;
		}
		bufctl = bufctl->next;
	}
	return NULL;
}

void *slab_allocate(slab_cache_t *cache)
{
	spin_lock(&cache->lock);
	struct slab *slab = cache->slab_list;
	while(slab)
	{
		void *obj = slab_allocate_from_slab(slab);
		if(obj)
		{
#if DEBUG_SLAB
			printk("cache %s returning %p\n", cache->name, obj);
#endif
			spin_unlock(&cache->lock);
			return obj;
		}
		if(!slab->next)
		{
			/* Expand the cache by adding a new slab */
			struct slab *nslab = slab_create_slab(cache->size, cache);
			if(!nslab)
			{
				spin_unlock(&cache->lock);
				return errno = ENOMEM, NULL;
			}
			slab->next = nslab;
			nslab->prev = slab;
		}
		slab = slab->next;
	}
	spin_unlock(&cache->lock);
	return NULL;
}

void slab_free_from_slab(struct slab *slab, void *addr, bool is_pool)
{
	bufctl_t *bufctl = slab->bufctls;
	while(bufctl)
	{
		if(bufctl->buf == addr)
		{
			bufctl->inuse = is_pool ? BUFCTL_FREE : BUFCTL_UNUSED;
			return;
		}
		bufctl = bufctl->next;
	}
}

void slab_free(slab_cache_t *cache, void *addr)
{
	/* I don't need to lock anything here I think */
	struct slab *slab = cache->slab_list;
	while(slab)
	{
		uintptr_t lower_limit = (uintptr_t) slab->buf;
		uintptr_t upper_limit = (uintptr_t) slab->buf + slab->size;
		
		if((uintptr_t) addr >= lower_limit && (uintptr_t) addr < upper_limit)
		{
			/* It's in this slab, free it */
			slab_free_from_slab(slab, addr, cache->flags & SLAB_FLAG_POOL);
			return;
		}
		slab = slab->next;
	}
}

void slab_purge_slab(struct slab *slab, slab_cache_t *cache)
{
	bufctl_t *bufctl = slab->bufctls;
	
	/* Look for BUFCTL_UNUSED bufs, call their dtor, and mark them as free */
	while(bufctl)
	{
		if(bufctl->inuse == BUFCTL_UNUSED)
		{
			if(cache->dtor)
				cache->dtor(bufctl->buf);
			
			bufctl->inuse = BUFCTL_FREE;
		}
		bufctl = bufctl->next;
	}
}

void slab_purge(slab_cache_t *cache)
{
	struct slab *slab = cache->slab_list;
	while(slab)
	{
		slab_purge_slab(slab, cache);
		slab = slab->next;
	}
}

void slab_destroy_slab(struct slab *slab)
{
	/* Free every bufctl */
	bufctl_t *bufctl = slab->bufctls;
	while(bufctl)
	{
		bufctl_t *this = bufctl;
		bufctl = bufctl->next;
		free(this);
	}
	vfree(slab->buf, vm_align_size_to_pages(slab->size));
}

void slab_destroy(slab_cache_t *cache)
{
	spin_lock(&cache->lock);
	/* First destroy the slabs */
	struct slab *slab = cache->slab_list;
	while(slab)
	{
		slab_destroy_slab(slab);
		struct slab *this = slab;
		slab = slab->next;
		free(this);
	}
	if(cache->prev)
		cache->prev->next = cache->next;
	if(cache->next)
		cache->next->prev = cache->prev;
	if(cache == first_slab)
	{
		first_slab = cache->next;
	}
	if(cache == last_slab)
	{
		last_slab = cache->prev;
	}
	free(cache);
}

static size_t slab_count_objs_in(struct slab *slab)
{
	bufctl_t *bufctl = slab->bufctls;
	size_t nr_objs = 0;

	while(bufctl)
	{
		++nr_objs;
		bufctl = bufctl->next;
	}
	
	return nr_objs;
}

int slab_populate(slab_cache_t *cache, size_t nr_objs)
{
	struct slab *slab = cache->slab_list;
	while(slab)
	{
		nr_objs -= slab_count_objs_in(slab);
		slab = slab->next;
	}
	slab = cache->slab_list;
	while(slab->next) slab = slab->next;

	while(nr_objs)
	{
		struct slab *slb = slab_create_slab(cache->size, cache);
		
		if(!slb)
			return -1;

		slab->next = slb;
		slab = slab->next;

		size_t nr_objs_in_slab = slab_count_objs_in(slb);
		if(nr_objs_in_slab > nr_objs)
			nr_objs = 0;
		else
			nr_objs -= nr_objs_in_slab;
	}

	return 0;
}
