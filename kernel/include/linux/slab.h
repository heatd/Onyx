#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <onyx/mm/slab.h>
#include <linux/gfp.h>
#include <linux/cache.h>

#define kmem_cache slab_cache
#define krealloc_array kreallocarray

static inline void *kzalloc(size_t len, gfp_t gfp)
{
    return kcalloc(len, 1, gfp);
}

static inline void *kmalloc_array(size_t n, size_t len, gfp_t gfp)
{
    return kcalloc(n, len, gfp);
}

/* TODO: proper... */
static inline void *kvmalloc_array(size_t n, size_t len, gfp_t gfp)
{
    return kmalloc_array(n, len, gfp);
}

static inline void *kvzalloc(size_t len, gfp_t gfp)
{
    return kzalloc(len, gfp);
}

static inline void linux_kfree(const void *p)
{
    kfree((void *) p);
}

#define kfree(p) linux_kfree(p)

#define kmalloc_node_track_caller(size, gfp, nid) kmalloc(size, gfp)

size_t ksize(void *ptr);

struct list_lru;

static inline void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
			   gfp_t gfpflags)
{
    return kmem_cache_alloc(s, gfpflags);
}

#endif
