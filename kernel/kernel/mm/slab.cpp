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

memory_pool<slab_cache, MEMORY_POOL_USE_VM> slab_cache_pool;

#define KMEM_CACHE_KEEP_THRESHOLD 131072

struct bufctl;

/**
 * Commentary on the allocator's design:
 * It resembles a very traditional slab allocator as described by [Bonwick, 94]. The big
 * difference is that we disregard the caching part of the slab allocator as it has not
 * proven useful in Linux, and others.
 *
 * Slab caches are collections of slabs. They have free slabs, partial slabs, full slabs.
 * Full slabs are fully allocated, partial slabs are partially allocated, free slabs are free.
 * Free slabs stay around until someone purges them, UNLESS the objsize is too large (the
 * threshold right now is 128KiB, but it is bound to change).
 *
 * Every object, for now, requires at least 16 byte alignment (and power of 2 alignment).
 *
 * Each slab cache, if not explicitly disabled or if size isn't too big, has percpu caches
 * which hold magazines (atm, up to 128 elements) of objects.
 * Ideally, you allocate and free straight from/to these, bypassing locking. The size of a
 * batch (the allocation/freeing unit) derives from the size of your object.
 */

struct slab
{
    unsigned long canary;
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

#define SLAB_CANARY 0x00600DBAAE600DBA

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
 * @param alignment Alignment of each object
 * @param flags Flags (see KMEM_CACHE_*)
 * @param ctor Unused
 * @return Pointer to the new slab_cache, or nullptr in case of an error
 */
struct slab_cache *kmem_cache_create(const char *name, size_t size, size_t alignment,
                                     unsigned int flags, void (*ctor)(void *))
{
    auto c = slab_cache_pool.allocate();
    if (!c)
    {
        return nullptr;
    }

    c->name = name;
    c->objsize = size;
    c->actual_objsize = size;
#ifdef CONFIG_KASAN
    c->redzone = kasan_get_redzone_size(c->objsize) * 2;
#else
    c->redzone = 0;
#endif
    c->flags = flags;

    // Minimum object alignment is 16
    c->alignment = alignment;

    if (c->alignment < 16)
        c->alignment = 16;

    // c->alignment = count_bits(c->alignment) != 1 ? 1 << (ilog2(c->alignment) + 1) : c->alignment;

    // If the creator wants it, align it to cache line sizes
    // TODO: Figure this out from architectural code
    if (flags & KMEM_CACHE_HWALIGN)
    {
        c->alignment = ALIGN_TO(c->alignment, 64);
    }

    c->objsize = ALIGN_TO(c->objsize, c->alignment);
    c->redzone = ALIGN_TO(c->redzone, c->alignment);

    if (c->objsize > PAGE_SIZE)
    {
        // If these objects are too large, opt out of percpu batch allocation
        c->flags |= KMEM_CACHE_NOPCPU;
    }

    c->ctor = ctor;

    INIT_LIST_HEAD(&c->free_slabs);
    INIT_LIST_HEAD(&c->partial_slabs);
    INIT_LIST_HEAD(&c->full_slabs);
    spinlock_init(&c->lock);
    c->nr_objects = 0;
    c->active_objects = 0;
    c->npartialslabs = c->nfreeslabs = c->nfullslabs = 0;

    for (auto &pcpu : c->pcpu)
    {
        pcpu.size = 0;
    }

    if (c->objsize > 256)
        c->mag_limit = 64;
    else if (c->objsize > 1024)
        c->mag_limit = 32;
    else
        c->mag_limit = SLAB_CACHE_PERCPU_MAGAZINE_SIZE;

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
ALWAYS_INLINE static inline void kmem_move_slab_to_full(struct slab *s, bool free)
{
    list_remove(&s->slab_list_node);
    list_add_tail(&s->slab_list_node, &s->cache->full_slabs);
    if (free)
        s->cache->nfreeslabs--;
    else
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
        kmem_move_slab_to_full(s, false);
    }

    ret->flags = 0;

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
    auto effobjsize = cache->objsize + cache->redzone;
    if (effobjsize < PAGE_SIZE / 8)
    {
        // Small object, allocate a single page
        return PAGE_SIZE;
    }
    else
    {
        // Temporary, should find a better heuristic
        return cul::align_up2(effobjsize * 24 + sizeof(struct slab), (size_t) PAGE_SIZE);
    }
}

/**
 * @brief Calculate the number of objects of each slab for a given slab cache
 *
 * @param cache Slab cache
 * @return Size of each slab
 */
static inline size_t kmem_calc_slab_nr_objs(struct slab_cache *cache)
{
    auto effobjsize = cache->objsize + cache->redzone;
    if (effobjsize < PAGE_SIZE / 8)
    {
        // Small object, allocate a single page
        return PAGE_SIZE / effobjsize;
    }
    else
    {
        // Temporary, should find a better heuristic
        return 24;
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

    auto phys = MAPPING_INFO_PADDR(info);
    return phys_to_page(phys);
}

/**
 * @brief Convert a pointer to its slab
 * This function panics if the pointer is bad.
 *
 * @param mem Pointer
 * @return Pointer to the slab
 */
struct slab *kmem_pointer_to_slab(void *mem)
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
 * @brief Convert a pointer to its slab
 * This function returns null if its not part of a slab.
 *
 * @param mem Pointer to memory
 * @return struct slab, or nullptr
 */
struct slab *kmem_pointer_to_slab_maybe(void *mem)
{
    unsigned long info = get_mapping_info(mem);
    if (!(info & PAGE_PRESENT)) [[unlikely]]
    {
        return nullptr;
    }

    auto phys MAPPING_INFO_PADDR(info);
    auto page = phys_to_page(phys);

    struct slab *s = (struct slab *) page->priv;
    return s;
}

/**
 * @brief Create a slab for a given cache
 *
 * @param cache Slab cache
 * @param flags Allocation flags
 * @return A pointer to the new slab, or nullptr in OOM situations.
 */
NO_ASAN static struct slab *kmem_cache_create_slab(struct slab_cache *cache, unsigned int flags)
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
    const size_t nr_objects = useful_size / (cache->objsize + cache->redzone);

    struct bufctl *first = nullptr;
    struct bufctl *last = nullptr;
    // Setup objects and chain them together
    for (size_t i = 0; i < nr_objects; i++, ptr += cache->objsize)
    {
        const auto redzone = cache->redzone / 2;
#ifdef CONFIG_KASAN
        asan_poison_shadow((unsigned long) ptr, redzone, KASAN_LEFT_REDZONE);
#endif
        ptr += redzone;

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

#ifdef CONFIG_KASAN
        asan_poison_shadow((unsigned long) ptr, cache->objsize, KASAN_REDZONE);
#endif
        last = ctl;
        ptr += cache->objsize;
#ifdef CONFIG_KASAN
        asan_poison_shadow((unsigned long) ptr, redzone, KASAN_REDZONE);
#endif
        ptr += redzone;
        ptr -= cache->objsize;
    }

    // Setup the struct slab at the end of the allocation
    struct slab *slab = (struct slab *) (start + useful_size);
    slab->canary = SLAB_CANARY;
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

#ifdef CONFIG_KASAN
    asan_poison_shadow((unsigned long) slab, sizeof(struct slab), KASAN_REDZONE);
#endif

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
 * This function is used when slab caches opt out of percpu allocation.
 *
 * @param cache Slab cache
 * @param flags Allocation flags
 * @return Allocated object, or nullptr in OOM situations.
 */
void *kmem_cache_alloc_nopcpu(struct slab_cache *cache, unsigned int flags)
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

static int kmem_cache_alloc_refill_mag(struct slab_cache *cache,
                                       struct slab_cache_percpu_context *pcpu, unsigned int flags)
{
    // Lets attempt to allocate a batch (half our stack)
    scoped_lock g{cache->lock};

    const auto objs_per_slab = kmem_calc_slab_nr_objs(cache);
    const auto batch_size = cache->mag_limit / 2;
    auto nr_slabs = objs_per_slab / batch_size;
    if (objs_per_slab % batch_size)
        nr_slabs++;

    for (size_t i = 0; i < nr_slabs; i++)
    {
        bool isfree = false;
        struct slab *slab;
        if (cache->npartialslabs)
        {
            assert(!list_is_empty(&cache->partial_slabs));
            slab = container_of(list_first_element(&cache->partial_slabs), struct slab,
                                slab_list_node);
        }
        else if (cache->nfreeslabs)
        {
            assert(!list_is_empty(&cache->free_slabs));
            slab =
                container_of(list_first_element(&cache->free_slabs), struct slab, slab_list_node);
            isfree = true;
        }
        else
        {
            slab = kmem_cache_create_slab(cache, flags);
            if (!slab)
            {
                // Only fail on memory allocation failure if we were allocating extra
                return i == 0 ? -1 : 0;
            }
            isfree = true;
        }

        // Fill up our magazine with a batch of objects
        bufctl *buf = slab->object_list;
        size_t avail = slab->nobjects - slab->active_objects;

        for (size_t j = 0; j < avail; j++)
        {
            if (pcpu->size == batch_size)
            {
                // If we're here, we're stopping in the middle of a slab
                // because of that, move it to partial (from free) and get out.
                if (isfree)
                    kmem_move_slab_to_partial(slab, isfree);
                goto out;
            }

            if (buf->flags != BUFCTL_PATTERN_FREE)
                panic("Bad buf %p, slab %p", buf, slab);

            pcpu->magazine[pcpu->size++] = (void *) buf;
            slab->object_list = (bufctl *) buf->next;
            buf = (bufctl *) buf->next;
            slab->active_objects++;
        }

        // We used up the whole slab, move it to full
        kmem_move_slab_to_full(slab, isfree);
    }

out:
    return 0;
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
    if (cache->flags & KMEM_CACHE_NOPCPU) [[unlikely]]
    {
        auto ret = kmem_cache_alloc_nopcpu(cache, flags);
        if (ret)
        {
#ifdef CONFIG_KASAN
            asan_unpoison_shadow((unsigned long) ret, cache->actual_objsize);
#endif
        }
        return ret;
    }

    // Disable preemption so we can safely touch the percpu data
    sched_disable_preempt();

    auto pcpu = &cache->pcpu[get_cpu_nr()];

    pcpu->touched.store(1, mem_order::release);

    if (!pcpu->size) [[unlikely]]
    {
        // If our magazine is empty, lets refill it
        if (kmem_cache_alloc_refill_mag(cache, pcpu, flags) < 0)
        {
            pcpu->touched.store(0, mem_order::release);
            sched_enable_preempt();
            return errno = ENOMEM, nullptr;
        }
    }

    // If we have objects on our magazine, pop one out and
    // return.
    auto ret = pcpu->magazine[--pcpu->size];
    ((bufctl *) ret)->flags = 0;

    pcpu->touched.store(0, mem_order::release);

    sched_enable_preempt();

#ifdef CONFIG_KASAN
    asan_unpoison_shadow((unsigned long) ret, cache->actual_objsize);
#endif

    return ret;
}

/**
 * @brief Free a given slab and give it back to the page backend
 * The given slab will be properly dissociated from its slab cache
 *
 * @param slab Slab to free
 */
static void kmem_cache_free_slab(struct slab *slab);

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
        if (cache->objsize >= KMEM_CACHE_KEEP_THRESHOLD) [[unlikely]]
        {
            // Free the slab, since these objects are way too large
            // we may as well assume they're a one-off allocation, as they
            // usually are.
            kmem_cache_free_slab(slab);
            cache->npartialslabs--;
        }
        else
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
static void kfree_nopcpu(void *ptr)
{
    auto slab = kmem_pointer_to_slab(ptr);
    auto cache = slab->cache;

#ifdef CONFIG_KASAN
    asan_poison_shadow((unsigned long) ptr, cache->objsize, KASAN_FREED);
#endif

    scoped_lock g{cache->lock};
    kmem_free_to_slab(cache, slab, ptr);
}

void kmem_cache_return_pcpu_batch(struct slab_cache *cache, struct slab_cache_percpu_context *pcpu)
{
    scoped_lock g{cache->lock};
    auto size = cache->mag_limit;
    auto batchsize = size / 2;
    for (int i = 0; i < batchsize; i++)
    {
        auto ptr = pcpu->magazine[i];
        auto slab = kmem_pointer_to_slab(ptr);

        if (slab->cache != cache) [[unlikely]]
            panic("slab: Pointer %p was returned to the wrong cache\n", ptr);
        ((bufctl *) ptr)->flags = 0;
        kmem_free_to_slab(cache, slab, ptr);
        pcpu->size--;
    }

    // Unlock the cache since we're about to do an expensive-ish memmove
    g.unlock();

    memmove(pcpu->magazine, &pcpu->magazine[batchsize], (size - pcpu->size) * sizeof(void *));
}

static void kmem_cache_free_pcpu(struct slab_cache *cache, void *ptr)
{
    bufctl *buf = (bufctl *) ptr;

    if ((unsigned long) ptr % cache->alignment) [[unlikely]]
    {
        panic("slab: Bad pointer %p", ptr);
    }

    if (buf->flags == BUFCTL_PATTERN_FREE) [[unlikely]]
    {
        panic("slab: Double free at %p\n", ptr);
    }

#ifdef CONFIG_KASAN
    asan_poison_shadow((unsigned long) ptr, cache->objsize, KASAN_FREED);
#endif

    sched_disable_preempt();

    auto pcpu = &cache->pcpu[get_cpu_nr()];

    pcpu->touched.store(1, mem_order::release);

    if (pcpu->size == cache->mag_limit) [[unlikely]]
    {
        kmem_cache_return_pcpu_batch(cache, pcpu);
    }
    else
    {
        pcpu->magazine[pcpu->size++] = ptr;
        buf->flags = BUFCTL_PATTERN_FREE;
    }

    pcpu->touched.store(0, mem_order::release);

    sched_enable_preempt();
}

#ifdef CONFIG_KASAN

void kasan_kfree(void *ptr, size_t chunk_size)
{
    bufctl *buf = (bufctl *) ptr;

    if (buf->flags == BUFCTL_PATTERN_FREE) [[unlikely]]
    {
        panic("slab: Double free at %p\n", ptr);
    }

    buf->flags = BUFCTL_PATTERN_FREE;
    asan_poison_shadow((unsigned long) ptr, chunk_size, KASAN_FREED);
    kasan_quarantine_add_chunk(buf, chunk_size);
}

#endif
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

#ifdef CONFIG_KASAN
    kasan_kfree(ptr, cache->objsize);
    return;
#endif

    if (cache->flags & KMEM_CACHE_NOPCPU)
        return kfree_nopcpu(ptr);

    kmem_cache_free_pcpu(cache, ptr);
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
    if (!ptr) [[unlikely]]
        return;

#ifdef CONFIG_KASAN
    kasan_kfree(ptr, cache->objsize);
    return;
#endif

    if (cache->flags & KMEM_CACHE_NOPCPU) [[unlikely]]
        return kfree_nopcpu(ptr);
    kmem_cache_free_pcpu(cache, ptr);
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

static void kmem_purge_local_cache(struct slab_cache *cache)
{
    auto pcpu = &cache->pcpu[get_cpu_nr()];

    // We use this cpu local atomic to know if we were touching
    // pcpu structures at that moment.
    if (pcpu->touched.load(mem_order::relaxed))
        return;

    // Cache lock is implicitly held.

    for (int i = 0; i < pcpu->size; i++)
    {
        auto ptr = pcpu->magazine[i];
        auto slab = kmem_pointer_to_slab(ptr);

        if (slab->cache != cache) [[unlikely]]
            panic("slab: Pointer %p was returned to the wrong cache\n", ptr);
        ((bufctl *) ptr)->flags = 0;
        kmem_free_to_slab(cache, slab, ptr);
    }

    pcpu->size = 0;
}

/**
 * @brief Purge a cache, unlocked
 *
 * @param cache Slab cache
 */
static void __kmem_cache_purge(struct slab_cache *cache)
{
#ifdef CONFIG_KASAN
    // Flushing the KASAN quarantine is important as to let objects go back to the slabs
    kasan_flush_quarantine();
#endif

    sched_disable_preempt();

    smp::sync_call_with_local([](void *ctx) { kmem_purge_local_cache((slab_cache *) ctx); }, cache,
                              cpumask::all(),
                              [](void *ctx) { kmem_purge_local_cache((slab_cache *) ctx); }, cache);

    sched_enable_preempt();

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

        __kmem_cache_purge(cache);

        if (cache->npartialslabs || cache->nfullslabs)
        {
            panic("slab: Tried to destroy cache %s (%p) which has live objects\n", cache->name,
                  cache);
        }

        list_remove(&cache->cache_list_node);
    }

    // Destroy the slab cache itself
    slab_cache_pool.free(cache);
}

#define KMALLOC_NR_CACHES 22

char kmalloc_cache_names[KMALLOC_NR_CACHES][20];
struct slab_cache *kmalloc_caches[KMALLOC_NR_CACHES];

void kmalloc_init()
{
    for (size_t i = 0; i < KMALLOC_NR_CACHES; i++)
    {
        // We start at 16 bytes
        size_t size = 1UL << (4 + i);
        snprintf(kmalloc_cache_names[i], 20, "kmalloc-%zu", size);
        kmalloc_caches[i] = kmem_cache_create(kmalloc_cache_names[i], size, 0, 0, nullptr);
        if (!kmalloc_caches[i])
            panic("Early out of memory\n");
    }
}

static inline int size_to_order(size_t size)
{
    if (size < 2) [[unlikely]]
        return 0;

    size_t order = ilog2(size - 1) + 1;
    if (order < 4) [[unlikely]]
        order = 4;
    order -= 4;

    if (order >= KMALLOC_NR_CACHES) [[unlikely]]
        return -1;
    return (int) order;
}

void *kmalloc(size_t size, int flags)
{
    auto order = size_to_order(size);

    if (order < 0)
        return nullptr;

    void *ret = kmem_cache_alloc(kmalloc_caches[order], 0);

    if (ret)
    {
        // If KASAN is on, poison the remainder (objsize - alloc_size) of the allocation.
#ifdef CONFIG_KASAN
        auto cacheobjsize = kmalloc_caches[order]->objsize;
        if (size - cacheobjsize)
            asan_poison_shadow((unsigned long) ret + size, cacheobjsize - size, KASAN_REDZONE);
#endif
    }

    return ret;
}

void *malloc(size_t size)
{
    return kmalloc(size, 0);
}

void free(void *ptr)
{
    return kfree(ptr);
}

void *calloc(size_t nr, size_t size)
{
    if (array_overflows(nr, size))
        return errno = EOVERFLOW, nullptr;

    const auto len = nr * size;

    void *ptr = malloc(len);
    if (!ptr) [[unlikely]]
    {
        return errno = ENOMEM, nullptr;
    }

    memset(ptr, 0, len);

    return ptr;
}

void *realloc(void *ptr, size_t size)
{
    if (!ptr)
        return malloc(size);

    auto old_slab = kmem_pointer_to_slab(ptr);

    if (old_slab->cache->objsize >= size)
    {
        // If KASAN is on, (un)poison the remainder (objsize - alloc_size) of the allocation.
#ifdef CONFIG_KASAN
        auto cacheobjsize = old_slab->cache->objsize;
        asan_unpoison_shadow((unsigned long) ptr, size);
        if (size - cacheobjsize)
            asan_poison_shadow((unsigned long) ptr + size, cacheobjsize - size, KASAN_REDZONE);
#endif
        return ptr;
    }

    auto newbuf = malloc(size);
    if (!newbuf)
        return nullptr;
    memcpy(newbuf, ptr, size);
    kfree(ptr);
    return newbuf;
}

int posix_memalign(void **pptr, size_t align, size_t len)
{
    *pptr = nullptr;
    return -1;
}

void *reallocarray(void *ptr, size_t m, size_t n)
{
    if (array_overflows(m, n))
        return errno = EOVERFLOW, nullptr;
    return realloc(ptr, n * m);
}

#ifdef CONFIG_KASAN

void kmem_free_kasan(void *ptr)
{
    auto slab = kmem_pointer_to_slab(ptr);
    assert(slab != nullptr);
    ((bufctl *) ptr)->flags = 0;
    kmem_free_to_slab(slab->cache, slab, ptr);
}

/**
 * @brief Print KASAN-relevant info for this mem-slab
 *
 * @param mem Pointer to the memory
 * @param slab Pointer to its slab
 */
void kmem_cache_print_slab_info_kasan(void *mem, struct slab *slab)
{
    const char *status =
        (slab->active_objects == 0 ? "free"
                                   : (slab->active_objects == slab->nobjects ? "full" : "partial"));

    printk("%p is apart of cache %s slab %p - slab status %s\n", mem, slab->cache->name, slab,
           status);
    // Pad "Memory information: " for the next info dump
    printk("                    ");
}

#endif
