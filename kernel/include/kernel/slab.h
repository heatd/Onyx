/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SLAB_H
#define _KERNEL_SLAB_H
#include <stdint.h>
#include <stddef.h>

#include <kernel/spinlock.h>
#include <kernel/list.h>

#define BUFCTL_FREE	0
#define BUFCTL_INUSE	1
#define BUFCTL_UNUSED	2
typedef struct bufctl
{
	struct bufctl *prev, *next;
	int inuse;
	void *buf;
} bufctl_t;
struct slab
{
	bufctl_t *bufctls;
	void *buf;
	size_t size;
	struct slab *prev, *next;
};
typedef struct cache
{
	const char *name;
	size_t size;
	size_t alignment;
	void (*ctor)(void*);
	void (*dtor)(void*);
	struct slab *slab_list;
	spinlock_t lock;
	struct cache *prev, *next;
} slab_cache_t;
#ifdef __cplusplus
extern "C" {
#endif
slab_cache_t *slab_create(const char *name, size_t size_obj, size_t alignment, int flags, void (*ctor)(void*), void (*dtor)(void*));
void *slab_allocate(slab_cache_t *cache);
void slab_free(slab_cache_t *cache, void *addr);
void slab_purge(slab_cache_t *cache);
void slab_destroy(slab_cache_t *cache);
#ifdef __cplusplus
}
#endif
#endif
