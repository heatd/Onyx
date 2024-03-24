/*
 * Copyright (c) 2919 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/init.h>
#include <onyx/local_lock.h>
#include <onyx/page.h>
#include <onyx/percpu.h>
#include <onyx/vm.h>

extern unsigned char __percpu_start;
extern unsigned char __percpu_end;
extern unsigned char percpu_base;

/* Define errno somewhere */
PER_CPU_VAR(int __true_errno) = 0;

PER_CPU_VAR(unsigned long __cpu_base) = 0;

int *__errno_location()
{
    return get_per_cpu_ptr(__true_errno);
}

bool percpu_inited = false;

unsigned long *percpu_bases = NULL;
unsigned long nr_bases = 0;

void percpu_add_percpu(unsigned long base)
{
    nr_bases++;
    percpu_bases =
        (unsigned long *) realloc((unsigned long *) percpu_bases, nr_bases * sizeof(unsigned long));
    assert(percpu_bases != NULL);
    percpu_bases[nr_bases - 1] = base;
}

unsigned long percpu_get_nr_bases()
{
    return nr_bases;
}

void percpu_init()
{
    size_t percpu_size = (unsigned long) &__percpu_end - (unsigned long) &__percpu_start;
    printf("percpu: .percpu size: %lu\n", percpu_size);

    void *buffer = (void *) get_per_cpu(__cpu_base);

    percpu_add_percpu((unsigned long) buffer);
    percpu_inited = true;
}

INIT_LEVEL_VERY_EARLY_CORE_ENTRY(percpu_init);

unsigned long percpu_init_for_cpu(unsigned int cpu)
{
    size_t percpu_size = (unsigned long) &__percpu_end - (unsigned long) &__percpu_start;

    void *buffer = zalloc(percpu_size);
    assert(buffer != NULL);

    /* TODO: percpu_add_percpu needs to be called in-order, should fix? */
    percpu_add_percpu((unsigned long) buffer);

    other_cpu_write(__cpu_base, (unsigned long) buffer, cpu);

    return (unsigned long) buffer;
}

unsigned long percpu_get_area(unsigned int cpu)
{
    if (cpu >= nr_bases)
        return 0;

    return percpu_bases[cpu];
}

int percpu_map_master_copy()
{
    size_t percpu_size = (unsigned long) &__percpu_end - (unsigned long) &__percpu_start;
    size_t nr_pages = vm_size_to_pages(percpu_size);
    unsigned long percpu_virtual_start = (unsigned long) &percpu_base;
    unsigned long phys_base =
        ((unsigned long) &percpu_base) - KERNEL_VIRTUAL_BASE + get_kernel_phys_offset();
    void *ret = map_pages_to_vaddr((void *) percpu_virtual_start, (void *) phys_base, nr_pages,
                                   VM_READ | VM_WRITE);
    return ret ? 0 : -1;
}

#ifndef CONFIG_SMP_NR_CPUS
#define CONFIG_SMP_NR_CPUS 64
#endif

unsigned long pcpu_first_chunk = 0;

#define PCPU_CHUNK_FLAG_PCPU (1 << 0)

struct percpu_chunk
{
    struct spinlock lock;
    u32 nr_free_objs;
    struct list_head list_node;
    u32 nr_objects;
    u16 data_area_off;
    u32 flags;
    u32 free_objs[];
};

enum chunk_category
{
    CHUNK_FREE = 0,
    CHUNK_PARTIAL,
    CHUNK_FULL,
    CHUNK_MAX
};

struct percpu_pcpu_state
{
    struct percpu_chunk *pcpu_partial;
};

struct percpu_cache
{
    size_t objsize;
    size_t chunksize;
    struct spinlock lock;
    struct local_lock pcpu_lock;
    struct list_head chunks[CHUNK_MAX];
    size_t nr_chunks[CHUNK_MAX];
    struct percpu_pcpu_state pcpu[CONFIG_SMP_NR_CPUS];
};

/* Preliminary lock ordering:
 *  cache->lock
    \--- chunk->lock
 * State changes always need to hold both locks, in that order */

__always_inline void *percpu_alloc_from_chunk(struct percpu_chunk *chunk)
{
    void *ret, *data_area;
    /* Pop the object from the chunk */
    spin_lock(&chunk->lock);

    DCHECK(chunk->nr_free_objs > 0);
    u32 off = chunk->free_objs[chunk->nr_free_objs - 1];
    chunk->nr_free_objs--;

    data_area = (void *) chunk + chunk->data_area_off;
    ret = (void *) (((unsigned long) data_area - pcpu_first_chunk) + off);

    spin_unlock(&chunk->lock);
    return ret;
}

static struct percpu_chunk *percpu_pop_chunk(struct percpu_cache *cache)
{
    struct percpu_chunk *chunk;

    spin_lock(&cache->lock);

#define CHUNK_FROM_CACHE(type)                                                                 \
    containerof_null_safe(                                                                     \
        list_is_empty(&cache->chunks[type]) ? NULL : list_first_element(&cache->chunks[type]), \
        struct percpu_chunk, list_node)

    chunk = CHUNK_FROM_CACHE(CHUNK_PARTIAL);
    if (chunk)
        goto out;

    chunk = CHUNK_FROM_CACHE(CHUNK_FREE);

out:
    spin_unlock(&cache->lock);
    return chunk;
}

static void percpu_put_chunk_on_lists(struct percpu_cache *cache, struct percpu_chunk *chunk)
{
    spin_lock(&cache->lock);
    spin_lock(&chunk->lock);

    enum chunk_category cat;

    if (chunk->nr_free_objs == 0)
        cat = CHUNK_FULL;
    else if (chunk->nr_free_objs == chunk->nr_objects)
        cat = CHUNK_FREE;
    else
        cat = CHUNK_PARTIAL;

    list_add_tail(&chunk->list_node, &cache->chunks[cat]);

    spin_unlock(&chunk->lock);
    spin_unlock(&cache->lock);
}

/**
 * @brief Refill a percpu cache's pcpu partial
 * This function releases the pcpu_lock, tries to grab a new pcpu partial and locks the pcpu_lock
 * again. If we switch CPUs, we put it back in the cache's global pool. If not, we use it as the
 * pcpu partial.
 *
 * @param cache Cache to refill
 * @param gfp_flags GFP flags
 * @return 0 on success, negative error codes
 */
static int percpu_refill_partial(struct percpu_cache *cache, unsigned int gfp_flags)
{
    struct percpu_chunk *chunk;
    local_unlock(&cache->pcpu_lock);

    chunk = percpu_pop_chunk(cache);
    if (chunk)
        goto out;

out:
    local_lock(&cache->pcpu_lock);
    struct percpu_pcpu_state *pcp = &cache->pcpu[get_cpu_nr()];
    if (pcp->pcpu_partial)
    {
        /* Put the new chunk back and use the current one */
        percpu_put_chunk_on_lists(cache, chunk);
    }
    else
        pcp->pcpu_partial = chunk;

    return 0;
}

void *percpu_cache_alloc(struct percpu_cache *cache, unsigned int gfp_flags)
{
    struct percpu_pcpu_state *state;
    void *ptr = NULL;

    local_lock(&cache->pcpu_lock);

    state = &cache->pcpu[get_cpu_nr()];
    if (unlikely(!state->pcpu_partial))
    {
        if (unlikely(percpu_refill_partial(cache, gfp_flags) < 0))
            goto out;
    }

    ptr = percpu_alloc_from_chunk(state->pcpu_partial);
    if (state->pcpu_partial->nr_free_objs == 0)
    {
        /* Put it on the global full list */
        percpu_put_chunk_on_lists(cache, state->pcpu_partial);
        state->pcpu_partial = NULL;
    }

out:
    local_unlock(&cache->pcpu_lock);
    return ptr;
}

void percpu_init2(void)
{
}
