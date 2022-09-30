/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/list.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/rwlock.h>
#include <onyx/vm.h>

#include <onyx/mm/pool.hpp>

static spinlock cache_list_lock;
static struct list_head cache_list = LIST_HEAD_INIT(cache_list);

memory_pool<slab_cache> slab_cache_pool;

struct bufctl;

struct slab
{
    union {
        void *start;
        struct page *pages;
    };

    size_t size;
    struct list_head slab_list_node;
    struct bufctl *object_list;
    size_t active_objects;
    size_t nobjects;
    struct slab_cache *cache;
};

#define BUFCTL_PATTERN_FREE 0xdeadbeef

struct bufctl
{
    void *next;
    unsigned int flags;
};

/**
 * @brief Create a slab cache
 *
 * @param name Name of the slab cache
 * @param size Size of each object
 * @param flags Flags (see KMEM_CACHE_*)
 * @param ctor Unused
 * @return Pointer to the new slab_cache, or nullptr in case of an error
 */
struct slab_cache *kmem_cache_create(char *name, size_t size, unsigned int flags,
                                     void (*ctor)(void *))
{
    auto c = slab_cache_pool.allocate();
    if (!c)
    {
        return nullptr;
    }

    c->name = name;
    c->objsize = size;
    c->flags = flags;

    // Minimum object alignment is size
    c->alignment = size;

    // ... but keeping 16 byte alignment like malloc is really important
    c->alignment = ALIGN_TO(c->alignment, 16);
    c->alignment = count_bits(c->alignment) != 1 ? 1 << (ilog2(c->alignment) + 1) : c->alignment;

    // If the creator wants it, align it to cache line sizes
    // TODO: Figure this out from architectural code
    if (flags & KMEM_CACHE_HWALIGN)
    {
        c->alignment = ALIGN_TO(c->alignment, 64);
    }

    c->objsize = ALIGN_TO(c->objsize, c->alignment);

    c->ctor = ctor;

    INIT_LIST_HEAD(&c->free_slabs);
    INIT_LIST_HEAD(&c->partial_slabs);
    INIT_LIST_HEAD(&c->full_slabs);
    spinlock_init(&c->lock);
    c->nr_objects = 0;
    c->active_objects = 0;
    c->npartialslabs = c->nfreeslabs = c->nfullslabs = 0;

    scoped_lock g{cache_list_lock};
    list_add_tail(&c->cache_list_node, &cache_list);
    return c;
}

#define ALWAYS_INLINE __attribute__((always_inline))

// Note: We can simplify the below slab state transitions to free <-> partial <-> full
// since each slab always has more than a single object.

/**
 * @brief Move a slab from its list to partial
 *
 * @param s Slab
 * @param free If in the free list. If not, it was in the full slabs list
 */
ALWAYS_INLINE static inline void kmem_move_slab_to_partial(struct slab *s, bool free)
{
    list_remove(&s->slab_list_node);
    list_add(&s->slab_list_node, &s->cache->partial_slabs);
    s->cache->npartialslabs++;
    if (free)
        s->cache->nfreeslabs--;
    else
        s->cache->nfullslabs--;
}

/**
 * @brief Move slab from partial to full
 *
 * @param s Slab
 */
ALWAYS_INLINE static inline void kmem_move_slab_to_full(struct slab *s)
{
    list_remove(&s->slab_list_node);
    list_add_tail(&s->slab_list_node, &s->cache->full_slabs);
    s->cache->npartialslabs--;
    s->cache->nfullslabs++;
}

/**
 * @brief Move slab from partial to free
 *
 * @param s Slab
 */
ALWAYS_INLINE static inline void kmem_move_slab_to_free(struct slab *s)
{
    list_remove(&s->slab_list_node);
    list_add_tail(&s->slab_list_node, &s->cache->free_slabs);
    s->cache->npartialslabs--;
    s->cache->nfreeslabs++;
}

/**
 * @brief Allocate an object from a slab
 *
 * @param s Slab
 * @param flags Flags
 * @return Allocated object. This function cannot return nullptr.
 */
static void *kmem_cache_alloc_from_slab(struct slab *s, unsigned int flags)
{
    assert(s->nobjects != s->active_objects);
    // Pop the first bufctl and return
    auto ret = s->object_list;
    if (ret == nullptr)
    {
        panic("Slab %p has inconsistent state\n", s);
    }

    if (ret->flags != BUFCTL_PATTERN_FREE)
    {
        panic("Object %p is corrupted\n", ret);
    }

    s->object_list = (struct bufctl *) s->object_list->next;

    auto old_active = s->active_objects++;

    if (old_active == 0)
    {
        // Was free, move to partial
        kmem_move_slab_to_partial(s, true);
    }
    else if (s->active_objects == s->nobjects)
    {
        // Was partial, now full
        kmem_move_slab_to_full(s);
    }

    return (void *) ret;
}

/**
 * @brief Allocate an object from the first slab on the partial list
 *
 * @param cache Slab cache
 * @param flags Flags
 * @return Allocated object
 */
static inline void *kmem_cache_alloc_from_partial(struct slab_cache *cache, unsigned int flags)
{
    struct slab *s =
        container_of(list_first_element(&cache->partial_slabs), struct slab, slab_list_node);

    return kmem_cache_alloc_from_slab(s, flags);
}

/**
 * @brief Allocate an object from the first slab on the free list
 *
 * @param cache Slab cache
 * @param flags Flags
 * @return Allocated object
 */
static inline void *kmem_cache_alloc_from_free(struct slab_cache *cache, unsigned int flags)
{
    struct slab *s =
        container_of(list_first_element(&cache->free_slabs), struct slab, slab_list_node);

    return kmem_cache_alloc_from_slab(s, flags);
}

/**
 * @brief Calculate the size of each slab for a given slab cache
 *
 * @param cache Slab cache
 * @return Size of each slab
 */
static inline size_t kmem_calc_slab_size(struct slab_cache *cache)
{
    if (cache->objsize < PAGE_SIZE / 8)
    {
        // Small object, allocate a single page
        return PAGE_SIZE;
    }
    else
    {
        // Temporary, should find a better heuristic
        return cul::align_up2(cache->objsize * 24 + sizeof(struct slab), (size_t) PAGE_SIZE);
    }
}

/**
 * @brief Convert a pointer to its struct page
 * This function panics if the pointer is bad.
 *
 * @param mem Pointer
 * @return struct page* for this pointer
 */
struct page *kmem_pointer_to_page(void *mem)
{
    unsigned long info = get_mapping_info(mem);
    if (!(info & PAGE_PRESENT)) [[unlikely]]
    {
        panic("slab: Bad pointer %p passed to free\n", mem);
    }

    auto phys MAPPING_INFO_PADDR(info);
    return phys_to_page(phys);
}

/**
 * @brief Convert a pointer to its slab
 * This function panics if the pointer is bad.
 *
 * @param mem Pointer
 * @return Pointer to the slab
 */
static inline struct slab *kmem_pointer_to_slab(void *mem)
{
    auto page = kmem_pointer_to_page(mem);
    struct slab *s = (struct slab *) page->priv;
    if (!s) [[unlikely]]
    {
        panic("slab: Bad pointer %p passed to free\n", mem);
    }

    return s;
}

/**
 * @brief Create a slab for a given cache
 *
 * @param cache Slab cache
 * @param flags Allocation flags
 * @return A pointer to the new slab, or nullptr in OOM situations.
 */
static struct slab *kmem_cache_create_slab(struct slab_cache *cache, unsigned int flags)
{
    char *start = nullptr;
    struct page *pages = nullptr;
    char *ptr = nullptr;

    size_t slab_size = kmem_calc_slab_size(cache);

    if (cache->flags & KMEM_CACHE_DIRMAP) [[unlikely]]
    {
        pages = alloc_pages(slab_size >> PAGE_SHIFT, PAGE_ALLOC_NO_ZERO | PAGE_ALLOC_CONTIGUOUS);
        if (!pages)
            return nullptr;
        start = (char *) PAGE_TO_VIRT(pages);
    }
    else
    {
        start = (char *) vmalloc(slab_size >> PAGE_SHIFT, VM_TYPE_HEAP, VM_READ | VM_WRITE);
        if (!start)
            return nullptr;
    }

    ptr = start;

    // TODO: Colouring? But geist said that maybe it's not necessary these days

    const size_t useful_size = slab_size - sizeof(struct slab);
    const size_t nr_objects = useful_size / cache->objsize;

    struct bufctl *first = nullptr;
    struct bufctl *last = nullptr;
    // Setup objects and chain them together
    for (size_t i = 0; i < nr_objects; i++, ptr += cache->objsize)
    {
        struct bufctl *ctl = (struct bufctl *) ptr;
        ctl->next = nullptr;
        ctl->flags = BUFCTL_PATTERN_FREE;
        if (last)
        {
            last->next = ctl;
        }
        else
        {
            first = ctl;
        }

        last = ctl;
    }

    // Setup the struct slab at the end of the allocation
    struct slab *slab = (struct slab *) (start + useful_size);
    slab->cache = cache;
    slab->active_objects = 0;
    slab->nobjects = nr_objects;
    slab->object_list = first;

    if (pages)
        slab->pages = pages;
    else
        slab->start = start;

    slab->size = slab_size;
    list_add_tail(&slab->slab_list_node, &cache->free_slabs);
    cache->nfreeslabs++;

    // Setup pointers to the slab in the struct pages
    size_t nr_pages = slab_size >> PAGE_SHIFT;
    for (size_t i = 0; i < nr_pages; i++)
    {
        auto ptr = start + (i << PAGE_SHIFT);
        auto page = kmem_pointer_to_page(ptr);
        page->priv = (unsigned long) slab;
    }

    return slab;
}

/**
 * @brief Allocate a slab and take an object from it
 *
 * @param cache Slab cache
 * @param flags Allocation flags
 * @return Allocated object, or nullptr in OOM situations
 */
static void *kmem_cache_alloc_noslab(struct slab_cache *cache, unsigned int flags)
{
    struct slab *s = kmem_cache_create_slab(cache, flags);
    if (!s)
        return nullptr;
    return kmem_cache_alloc_from_slab(s, flags);
}

/**
 * @brief Allocate an object from the slab
 * This function call be called in nopreempt/softirq context.
 *
 * @param cache Slab cache
 * @param flags Allocation flags
 * @return Allocated object, or nullptr in OOM situations.
 */
void *kmem_cache_alloc(struct slab_cache *cache, unsigned int flags)
{
    scoped_lock g{cache->lock};

    if (cache->npartialslabs != 0)
    {
        return kmem_cache_alloc_from_partial(cache, flags);
    }
    else if (cache->nfreeslabs != 0)
    {
        return kmem_cache_alloc_from_free(cache, flags);
    }

    return kmem_cache_alloc_noslab(cache, flags);
}

/**
 * @brief Free an object to its slab
 * This function panics on bad pointers.
 *
 * @param cache Slab's cache
 * @param slab Slab
 * @param ptr Pointer to the object
 */
static void kmem_free_to_slab(struct slab_cache *cache, struct slab *slab, void *ptr)
{
    if ((unsigned long) ptr % cache->alignment) [[unlikely]]
    {
        panic("slab: Bad pointer %p", ptr);
    }

    struct bufctl *ctl = (struct bufctl *) ptr;
    if (ctl->flags == BUFCTL_PATTERN_FREE)
    {
        panic("slab: Double free at %p", ptr);
    }

    ctl->next = nullptr;
    ctl->flags = BUFCTL_PATTERN_FREE;
    // This freed object is hot, so put it in the head of the slab list
    auto first = slab->object_list;
    slab->object_list = ctl;
    if (first)
        ctl->next = first;
    auto old_active = slab->active_objects--;

    if (old_active == slab->nobjects)
    {
        // Move full to partial
        kmem_move_slab_to_partial(slab, false);
    }
    else if (slab->active_objects == 0)
    {
        // Move partial to free
        kmem_move_slab_to_free(slab);
    }
}

/**
 * @brief Free a pointer to an object in a slab
 * This function panics on bad pointers. If NULL is given, it's a no-op.
 *
 * @param ptr Pointer to an object, or NULL.
 */
void kfree(void *ptr)
{
    if (!ptr) [[unlikely]]
        return;
    auto slab = kmem_pointer_to_slab(ptr);
    auto cache = slab->cache;
    scoped_lock g{cache->lock};
    kmem_free_to_slab(cache, slab, ptr);
}

/**
 * @brief Free a pointer to an object in a slab cache
 * This function panics on bad pointers. If NULL is given, it's a no-op.
 *
 * @param cache Slab cache
 * @param ptr Pointer to an object, or NULL.
 */
void kmem_cache_free(struct slab_cache *cache, void *ptr)
{
    return kfree(ptr);
}

/**
 * @brief Free a given slab and give it back to the page backend
 * The given slab will be properly dissociated from its slab cache
 *
 * @param slab Slab to free
 */
static void kmem_cache_free_slab(struct slab *slab)
{
    assert(slab->active_objects == 0);
    auto cache = slab->cache;

    // Free it from the free list

    list_remove(&slab->slab_list_node);

    // After freeing the slab we may no longer touch the struct slab
    if (cache->flags & KMEM_CACHE_DIRMAP)
    {
        free_pages(slab->pages);
    }
    else
    {
        vfree(slab->start, slab->size >> PAGE_SHIFT);
    }
}

/**
 * @brief Purge a cache, unlocked
 *
 * @param cache Slab cache
 */
static void __kmem_cache_purge(struct slab_cache *cache)
{
    if (!cache->nfreeslabs)
        return;

    list_for_every_safe (&cache->free_slabs)
    {
        auto s = container_of(l, struct slab, slab_list_node);
        kmem_cache_free_slab(s);
        cache->nfreeslabs--;
    }
}

/**
 * @brief Purge a cache
 * This function goes through every free slab and gives it back to the page allocator.
 * It does NOT touch partial or full slabs.
 *
 * @param cache Slab cache
 */
void kmem_cache_purge(struct slab_cache *cache)
{
    scoped_lock g{cache->lock};
    __kmem_cache_purge(cache);
}

/**
 * @brief Destroy a slab cache
 * This function destroys a slab cache, frees everything and removes it from the list
 * of slabs. If given a slab with active objects, it will panic.
 *
 * @param cache Slab cache
 */
void kmem_cache_destroy(struct slab_cache *cache)
{
    // Note: lock the cache list lock first, since we don't want memory reclamation
    // to possibly get in the way. Reclamation will do cache_list_lock -> cache->lock.

    {
        scoped_lock g{cache_list_lock};
        scoped_lock g2{cache->lock};

        if (cache->npartialslabs || cache->nfullslabs)
        {
            panic("slab: Tried to destroy cache %s (%p) which has live objects\n", cache->name,
                  cache);
        }

        __kmem_cache_purge(cache);

        list_remove(&cache->cache_list_node);
    }

    // Destroy the slab cache itself
    slab_cache_pool.free(cache);
}
