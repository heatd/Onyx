/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_MM_SLAB_H
#define _ONYX_MM_SLAB_H

#include <stddef.h>

#include <onyx/list.h>
#include <onyx/mm/kasan.h>
#include <onyx/spinlock.h>

#include <onyx/atomic.hpp>

#define SLAB_CACHE_PERCPU_MAGAZINE_SIZE 128

struct slab_cache_percpu_context
{
    void *magazine[SLAB_CACHE_PERCPU_MAGAZINE_SIZE];
    int size;
    atomic<int> touched;
} __align_cache;

struct slab_cache
{
    const char *name;
    struct list_head partial_slabs;
    struct list_head free_slabs;
    struct list_head full_slabs;
    size_t nr_objects;
    size_t active_objects;
    size_t alignment;
    size_t objsize;
    size_t actual_objsize;
    size_t redzone;
    size_t npartialslabs;
    size_t nfreeslabs;
    size_t nfullslabs;
    struct list_head cache_list_node;
    unsigned int flags;
    spinlock lock;
    void (*ctor)(void *);
    int mag_limit;
    // TODO: This is horrible. We need a way to allocate percpu memory,
    // and then either trim it or grow it when CPUs come online.
    struct slab_cache_percpu_context pcpu[CONFIG_SMP_NR_CPUS] __align_cache;
};

#define KMEM_CACHE_HWALIGN (1 << 0)
#define KMEM_CACHE_VMALLOC (1 << 1)
#define KMEM_CACHE_NOPCPU  (1 << 2)

/**
 * @brief Create a slab cache
 *
 * @param name Name of the slab cache
 * @param size Size of each object
 * @param alignment Alignment of each object
 * @param flags Flags (see KMEM_CACHE_*)
 * @param ctor Unused
 * @return Pointer to the new slab_cache, or nullptr in case of an error
 */
struct slab_cache *kmem_cache_create(const char *name, size_t size, size_t alignment,
                                     unsigned int flags, void (*ctor)(void *));

/**
 * @brief Allocate an object from the slab
 * This function call be called in nopreempt/softirq context.
 *
 * @param cache Slab cache
 * @param flags Allocation flags
 * @return Allocated object, or nullptr in OOM situations.
 */
void *kmem_cache_alloc(struct slab_cache *cache, unsigned int flags);

/**
 * @brief Free a pointer to an object in a slab cache
 * This function panics on bad pointers. If NULL is given, it's a no-op.
 *
 * @param cache Slab cache
 * @param ptr Pointer to an object, or NULL.
 */
void kmem_cache_free(struct slab_cache *cache, void *ptr);

void *kmalloc(size_t size, int flags);

/**
 * @brief Free a pointer to an object in a slab
 * This function panics on bad pointers. If NULL is given, it's a no-op.
 *
 * @param ptr Pointer to an object, or NULL.
 */
void kfree(void *ptr);

/**
 * @brief Purge a cache
 * This function goes through every free slab and gives it back to the page allocator.
 * It does NOT touch partial or full slabs.
 *
 * @param cache Slab cache
 */
void kmem_cache_purge(struct slab_cache *cache);

/**
 * @brief Destroy a slab cache
 * This function destroys a slab cache, frees everything and removes it from the list
 * of slabs. If given a slab with active objects, it will panic.
 *
 * @param cache Slab cache
 */
void kmem_cache_destroy(struct slab_cache *cache);

struct slab;

/**
 * @brief Convert a pointer to its slab
 * This function returns null if its not part of a slab.
 *
 * @param mem Pointer to memory
 * @return struct slab, or nullptr
 */
struct slab *kmem_pointer_to_slab_maybe(void *mem);

#ifdef CONFIG_KASAN

/**
 * @brief Print KASAN-relevant info for this mem-slab
 *
 * @param mem Pointer to the memory
 * @param slab Pointer to its slab
 */
void kmem_cache_print_slab_info_kasan(void *mem, struct slab *slab);
#endif

/**
 * @brief Shrink caches in order to free pages
 *
 * @param target_freep Target free pages
 */
void slab_shrink_caches(unsigned long target_freep);

#endif
