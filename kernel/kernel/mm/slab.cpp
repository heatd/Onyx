/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/cpu.h>
#include <onyx/list.h>
#include <onyx/mm/slab.h>
#include <onyx/modules.h>
#include <onyx/page.h>
#include <onyx/perf_probe.h>
#include <onyx/rwlock.h>
#include <onyx/stackdepot.h>
#include <onyx/vm.h>

#include <onyx/mm/pool.hpp>

static mutex cache_list_lock;
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
 * @brief Sits at the redzone and has debug information for KASAN support.
 *
 */
struct kasan_slab_obj_info
{
    depot_stack_handle_t alloc_stack;
    depot_stack_handle_t free_stack;
};

/**
 * @brief Free a given slab and give it back to the page backend
 * The given slab will be properly dissociated from its slab cache
 *
 * @param slab Slab to free
 */
static void kmem_cache_free_slab(struct slab *slab);

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
    c->flags = flags | KMEM_CACHE_VMALLOC;

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

    scoped_mutex g{cache_list_lock};
    list_add_tail(&c->cache_list_node, &cache_list);
    return c;
}

#define ALWAYS_INLINE __attribute__((always_inline))

#ifdef SLAB_DEBUG_COUNTS
/* Kept here and not in list.h, because this is a horrible pattern that should not be used for
 * !DEBUG */
static size_t list_calc_len(struct list_head *list)
{
    size_t len = 0;
    list_for_every (list)
        len++;
    return len;
}

#define KMEM_DCHECK(check, cache)     \
    if (!(check))                     \
    {                                 \
        kmem_dump_cache_debug(cache); \
        DCHECK(check);                \
    }

static struct mutex dump_cache_lock;
__noinline static void kmem_dump_cache_debug(struct slab_cache *cache)
{
    panic_start();
    mutex_lock(&dump_cache_lock);
    printk("slab: dumping cache %s - %p\n", cache->name, cache);
    printk("      nfreeslabs %lu, calculated %lu\n", cache->nfreeslabs,
           list_calc_len(&cache->free_slabs));
    printk("      npartialslabs %lu, calculated %lu\n", cache->npartialslabs,
           list_calc_len(&cache->partial_slabs));
    printk("      nfullslabs %lu, calculated %lu\n", cache->nfullslabs,
           list_calc_len(&cache->full_slabs));
    panic("bah");
}

__attribute__((optimize("no-optimize-sibling-calls"))) __noinline static void
kmem_assert_slab_count(struct slab_cache *cache)
{
    DCHECK(spin_lock_held(&cache->lock));
    KMEM_DCHECK(cache->nfreeslabs == list_calc_len(&cache->free_slabs), cache);
    KMEM_DCHECK(cache->npartialslabs == list_calc_len(&cache->partial_slabs), cache);
    KMEM_DCHECK(cache->nfullslabs == list_calc_len(&cache->full_slabs), cache);
}

#define ASSERT_SLAB_COUNT(cache) kmem_assert_slab_count(cache)
#else
#define ASSERT_SLAB_COUNT(cache)
#endif

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
    ASSERT_SLAB_COUNT(s->cache);
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
    ASSERT_SLAB_COUNT(s->cache);
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
    ASSERT_SLAB_COUNT(s->cache);
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
    if ((unsigned long) mem >= PHYS_BASE && (unsigned long) mem < PHYS_BASE_LIMIT) [[likely]]
    {
        unsigned long phys = ((unsigned long) mem - PHYS_BASE);
        return phys_to_page(phys);
    }

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
 * @param no_add Don't add the new slab to the list
 * @return A pointer to the new slab, or nullptr in OOM situations.
 */
NO_ASAN static struct slab *kmem_cache_create_slab(struct slab_cache *cache, unsigned int flags,
                                                   bool no_add)
{
    char *start = nullptr;
    struct page *pages = nullptr;
    char *ptr = nullptr;

    size_t slab_size = kmem_calc_slab_size(cache);

    if (!(cache->flags & KMEM_CACHE_VMALLOC)) [[likely]]
    {
        pages = alloc_pages(pages2order(slab_size >> PAGE_SHIFT),
                            PAGE_ALLOC_NO_ZERO | PAGE_ALLOC_CONTIGUOUS);
        if (!pages)
            return nullptr;
        start = (char *) PAGE_TO_VIRT(pages);
    }
    else
    {
        start = (char *) vmalloc(slab_size >> PAGE_SHIFT, VM_TYPE_HEAP, VM_READ | VM_WRITE, flags);
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

    if (!no_add)
    {
        list_add_tail(&slab->slab_list_node, &cache->free_slabs);
        cache->nfreeslabs++;
        ASSERT_SLAB_COUNT(cache);
    }

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
    /* Release the lock (we need it for allocation from the backend) */
    spin_unlock(&cache->lock);
    struct slab *s = kmem_cache_create_slab(cache, flags, true);
    spin_lock(&cache->lock);

    if (!s)
        return nullptr;

    /* TODO: This is redundant but alloc_from_slab insists on *moving* us from/to lists */
    list_add_tail(&s->slab_list_node, &cache->free_slabs);
    cache->nfreeslabs++;
    ASSERT_SLAB_COUNT(cache);
    void *obj = kmem_cache_alloc_from_slab(s, flags);
    DCHECK(obj != nullptr);

    return obj;
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

/**
 * @brief Pick a slab to refill from
 * @pre @cache is locked
 * @param cache Slab cache
 * @return Chosen slab, or NULL if there's no available slab
 */
static inline struct slab *kmem_pick_slab_for_refill(struct slab_cache *cache)
{
    /* Cache is locked */
    /* Pick out a slab from the partial list, or the free list. Prefer partial to reduce
     * fragmentation. */
    struct slab *slab = nullptr;
    if (cache->npartialslabs)
        slab = container_of(list_first_element(&cache->partial_slabs), struct slab, slab_list_node);
    else if (cache->nfreeslabs)
        slab = container_of(list_first_element(&cache->free_slabs), struct slab, slab_list_node);

    return slab;
}

/**
 * @brief Add a slab's objects to the pcpu magazine
 *
 * @pre cache is locked
 * @pre Preemption is disabled (pcpu is pinned)
 * @param cache Slab cache
 * @param pcpu Slab pcpu cache
 * @param slab Slab to add
 */
static void kmem_cache_reload_mag_with_slab(struct slab_cache *cache,
                                            struct slab_cache_percpu_context *pcpu,
                                            struct slab *slab)
{
    /* Preemption is off, cache is locked */
    struct bufctl *buf = slab->object_list;
    size_t avail = slab->nobjects - slab->active_objects;
    const int batch_size = cache->mag_limit / 2;

    for (size_t j = 0; j < avail; j++)
    {
        if (pcpu->size >= batch_size)
            break;

        if (buf->flags != BUFCTL_PATTERN_FREE)
            panic("Bad buf %p, slab %p", buf, slab);

        pcpu->magazine[pcpu->size++] = (void *) buf;
        slab->object_list = (bufctl *) buf->next;

        if (!buf->next && j + 1 != avail)
            panic("Corrupted buf %p, slab %p", buf, slab);

        buf = (bufctl *) buf->next;
        slab->active_objects++;
    }
}

/**
 * @brief Refill a magazine purely from partial and free slabs
 * This function does not allocate.
 *
 * @pre cache is locked
 * @pre Preemption is disabled
 * @param cache
 * @param pcpu
 * @return int
 */
static int kmem_cache_refill_mag_noalloc(struct slab_cache *cache,
                                         struct slab_cache_percpu_context *pcpu)
{
    /* Preemption is off, cache is locked */
    const size_t objs_per_slab = kmem_calc_slab_nr_objs(cache);
    const int batch_size = cache->mag_limit / 2;

    while (pcpu->size < batch_size)
    {
        bool is_partial;
        struct slab *slab = kmem_pick_slab_for_refill(cache);
        if (!slab)
        {
            int to_alloc = (batch_size - pcpu->size) / objs_per_slab;
            if ((batch_size - pcpu->size) % objs_per_slab)
                to_alloc++;
            return to_alloc;
        }

        is_partial = slab->active_objects > 0;
        /* Fill out the mags */
        kmem_cache_reload_mag_with_slab(cache, pcpu, slab);

        /* Note: three state changes are possible: PARTIAL -> FULL, FREE -> PARTIAL and FREE ->
         * FULL. */
        if (slab->active_objects == slab->nobjects)
            kmem_move_slab_to_full(slab, !is_partial);
        else if (!is_partial && slab->active_objects > 0)
            kmem_move_slab_to_partial(slab, true);
    }

    return 0;
}

/**
 * @brief Refill a magazine
 * Refill a magazine using partial+free slabs and/or allocated slabs.
 * This function may drop preemption (if allocating). Callers must re-fetch pcpu.
 * Whatever pcpu is valid at the end of the function is guaranteed to have at least one object in
 * the mag.
 *
 * @pre Preemption is off
 * @pre cache is unlocked
 * @param cache Slab cache
 * @param pcpu Slab percpu cache
 * @param flags GFP flags (see GFP_KERNEL, et al)
 * @return 0 on success, negative error codes
 */
static int kmem_cache_alloc_refill_mag(struct slab_cache *cache,
                                       struct slab_cache_percpu_context *pcpu, unsigned int flags)
{
    /* Preemption is off, cache is unlocked. The cache lock is only held in very specific points.
     * The lock must *not* be held when allocating slabs, as page allocation can sleep. */
    DEFINE_LIST(allocated_slabs);
    int slabs_to_alloc;
    int nslabs;

    spin_lock(&cache->lock);
    slabs_to_alloc = kmem_cache_refill_mag_noalloc(cache, pcpu);
    spin_unlock(&cache->lock);
    if (slabs_to_alloc == 0)
    {
        /* This is good, preemption was never reenabled, so pcpu is definitely the same. We never
         * needed to allocate more slabs. */
        return 0;
    }

    /* Release the pcpu. We're going to effectively drop it in a bit */
    pcpu->touched.store(0, mem_order::relaxed);

    sched_enable_preempt();
    /* Allocate N slabs and add them to allocated_slabs. These are temporarily isolated from the
     * cache, but will be added to the slab cache system when allocation finishes. */

    for (nslabs = 0; nslabs < slabs_to_alloc; nslabs++)
    {
        struct slab *s = kmem_cache_create_slab(cache, flags, true);
        if (!s)
        {
            /* If i == 0, this is definitely a failure. Else, just break the loop */
            if (nslabs == 0)
            {
                sched_disable_preempt();
                return -ENOMEM;
            }

            break;
        }

        /* For future allocations: it's *not* okay to use atomic reserves for batch filling. We just
         * use __GFP_ATOMIC for the first slab, and anything else is very much extra, thus hardly
         * "__GFP_ATOMIC". */
        flags &= ~__GFP_ATOMIC;
        list_add_tail(&s->slab_list_node, &allocated_slabs);
    }

    /* Pin ourselves again to a CPU and get its percpu cache. It may or may not be the same, and
     * that's okay. If we switched CPUs and overallocated, the remaining slabs will stay in the
     * cache's free slabs list. */
    sched_disable_preempt();
    pcpu = &cache->pcpu[get_cpu_nr()];
    pcpu->touched.store(1, mem_order::relaxed);

    spin_lock(&cache->lock);
    /* Splice the allocated_slabs to free_slabs */
    list_splice_tail(&allocated_slabs, &cache->free_slabs);
    cache->nfreeslabs += nslabs;

    kmem_cache_refill_mag_noalloc(cache, pcpu);
    DCHECK(pcpu->size > 0);

    spin_unlock(&cache->lock);

    /* Preemption is disabled, cache is unlocked, mag should hold at least one object */
    return 0;
}

#ifdef CONFIG_KASAN

#define KASAN_STACK_DEPTH 16

__always_inline void kmem_cache_post_alloc_kasan(struct slab_cache *cache, unsigned int flags,
                                                 void *object)
{
    struct kasan_slab_obj_info *info =
        (struct kasan_slab_obj_info *) ((u8 *) object - (cache->redzone / 2));
    unsigned long trace[KASAN_STACK_DEPTH];
    unsigned long nr =
        stack_trace_get((unsigned long *) __builtin_frame_address(0), trace, KASAN_STACK_DEPTH);
    info->alloc_stack = stackdepot_save_stack(trace, nr);
    info->free_stack = DEPOT_STACK_HANDLE_INVALID;

    asan_unpoison_shadow((unsigned long) object, cache->actual_objsize);
}

__always_inline void kasan_register_free(void *ptr, struct slab_cache *cache)
{
    struct kasan_slab_obj_info *info =
        (struct kasan_slab_obj_info *) ((u8 *) ptr - (cache->redzone / 2));
    unsigned long trace[KASAN_STACK_DEPTH];
    unsigned long nr =
        stack_trace_get((unsigned long *) __builtin_frame_address(0), trace, KASAN_STACK_DEPTH);
    info->free_stack = stackdepot_save_stack(trace, nr);
}

#else
__always_inline void kmem_cache_post_alloc_kasan(struct slab_cache *cache, unsigned int flags,
                                                 void *object)
{
}
#endif
/**
 * @brief Called after a successful allocation for post-alloc handling
 *
 * @param cache SLAB cache
 * @param flags Allocation flags
 * @param object Object that was allocated
 */
__always_inline void kmem_cache_post_alloc(struct slab_cache *cache, unsigned int flags,
                                           void *object)
{
    kmem_cache_post_alloc_kasan(cache, flags, object);
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
            kmem_cache_post_alloc(cache, flags, ret);
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
        int st = kmem_cache_alloc_refill_mag(cache, pcpu, flags);
        /* pcpu might've changed over refill_mag, so reload it */
        pcpu = &cache->pcpu[get_cpu_nr()];
        if (st < 0)
        {
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

    kmem_cache_post_alloc(cache, flags, ret);

    return ret;
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
        if (cache->objsize >= KMEM_CACHE_KEEP_THRESHOLD) [[unlikely]]
        {
            // Free the slab, since these objects are way too large
            // we may as well assume they're a one-off allocation, as they
            // usually are.
            kmem_cache_free_slab(slab);
            cache->npartialslabs--;
            ASSERT_SLAB_COUNT(cache);
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

void kasan_kfree(void *ptr, struct slab_cache *cache, size_t chunk_size)
{
    bufctl *buf = (bufctl *) ptr;

    if (buf->flags == BUFCTL_PATTERN_FREE) [[unlikely]]
    {
        panic("slab: Double free at %p\n", ptr);
    }

    buf->flags = BUFCTL_PATTERN_FREE;
    asan_poison_shadow((unsigned long) ptr, chunk_size, KASAN_FREED);
    kasan_register_free(ptr, cache);
#ifndef NOQUARANTINE
    kasan_quarantine_add_chunk(buf, chunk_size);
#else
    buf->flags = 0;
    if (cache->flags & KMEM_CACHE_NOPCPU)
        return kfree_nopcpu(ptr);

    kmem_cache_free_pcpu(cache, ptr);
#endif
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
    kasan_kfree(ptr, cache, cache->objsize);
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
    kasan_kfree(ptr, cache, cache->objsize);
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
    if (!(cache->flags & KMEM_CACHE_VMALLOC)) [[likely]]
    {
        free_pages(slab->pages);
    }
    else
    {
        vfree(slab->start, slab->size >> PAGE_SHIFT);
    }
}

struct slab_rendezvous
{
    unsigned int waiting_for_cpus;
    unsigned int ack;
};

static void kmem_purge_remote(struct slab_rendezvous *rndvz)
{
    __atomic_sub_fetch(&rndvz->waiting_for_cpus, 1, __ATOMIC_RELAXED);
    /* Orders prior loads and stores against the rndvz::ack read */
    smp_mb();
    /* Wait for the ack back from the shrinking cpu. Acquire semantics will make us observe
     * everything written from freeze_start to freeze_end. */
    while (!__atomic_load_n(&rndvz->ack, __ATOMIC_ACQUIRE))
        cpu_relax();
    /* Signal that we left the purge and no longer need rndvz. Relaxed does just fine here. */
    __atomic_sub_fetch(&rndvz->waiting_for_cpus, 1, __ATOMIC_RELAXED);
}

/**
 * @brief Start a slab allocator freeze
 * When the slab allocator is frozen, no one can enter the per-cpu "area" of any cache. That is to
 * say, cpus that were accessing their pcpu will be frozen, and new ones will not be able to get in.
 * Requires preemption to be disabled, in order for us to not migrate CPUs mid-freeze.
 *
 * @param rndvz Rendezvous structure
 */
static void kmem_slab_freeze_start(struct slab_rendezvous *rndvz)
{
    /* To start a freeze, we store the number of CPUs we're waiting for in a shared structure. As
     * IPIs hit CPUs, they decrement the count. When the count hits 0, we know every CPU has hit the
     * freeze and may start to reclaim (or whatever we need to do). See comments in
     * kmem_purge_remote for notes on the concurrency. */
    unsigned int to_sync = get_nr_cpus() - 1;
    rndvz->ack = 0;
    __atomic_store_n(&rndvz->waiting_for_cpus, to_sync, __ATOMIC_RELEASE);

    smp::sync_call([](void *ctx) { kmem_purge_remote((slab_rendezvous *) ctx); }, rndvz,
                   cpumask::all_but_one(get_cpu_nr()), SYNC_CALL_NOWAIT);

    while (__atomic_load_n(&rndvz->waiting_for_cpus, __ATOMIC_ACQUIRE) > 0)
        cpu_relax();
}

/**
 * @brief End a slab allocator freeze
 * End a slab allocator freeze and let cpus allocate again.
 * @param rndvz Rendezvous structure
 */
static void kmem_slab_freeze_end(struct slab_rendezvous *rndvz)
{
    rndvz->waiting_for_cpus = get_nr_cpus() - 1;
    /* Use release to make waiters see waiting_for_cpus before ack. It will also make prior stores
     * visible when ack is acquired. */
    __atomic_store_n(&rndvz->ack, 1, __ATOMIC_RELEASE);
}

/**
 * @brief Wait for all frozen cpus to leave the rendezvous period
 * Wait for all frozen cpus to leave rendezvous. After the wait,
 * we are guaranteed that @arg rndvz will not have any outstanding
 * references.
 * @param rndvz Rendezvous structure
 */
static void kmem_slab_freeze_wait(struct slab_rendezvous *rndvz)
{
    while (READ_ONCE(rndvz->waiting_for_cpus) > 0)
        cpu_relax();
}

/**
 * @brief Shrink all pcpu caches for a given cache
 * Empty the pcpu caches for all online CPUs, for a given cache.
 * If any given pcpu cache is "touched" (aka that cpu has a reference to it), skip it.
 * Requires the cache lock and a slab freeze to be in place.
 * @param cache Slab cache
 */
static void kmem_cache_shrink_pcpu_all(struct slab_cache *cache)
{
    /* For every CPU, flush the pcpu cache *if possible* */
    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        struct slab_cache_percpu_context *pcpu = &cache->pcpu[i];
        if (pcpu->touched.load(mem_order::relaxed) > 0)
            continue;
        for (int j = 0; j < pcpu->size; j++)
        {
            auto ptr = pcpu->magazine[j];
            auto slab = kmem_pointer_to_slab(ptr);

            if (slab->cache != cache) [[unlikely]]
                panic("slab: Pointer %p was returned to the wrong cache\n", ptr);
            ((bufctl *) ptr)->flags = 0;
            kmem_free_to_slab(cache, slab, ptr);
        }

        pcpu->size = 0;
    }
}

/**
 * @brief Release free slabs of a given cache up to a point
 * Release all free slabs up to a @arg target_frep. Requires the cache lock.
 *
 * @param cache Cache to trim
 * @param target_freep Target free pages. If we equal or exceed this mark, we return.
 * @return Estimation of freed pages
 */
static unsigned long kmem_cache_release_free_all(struct slab_cache *cache,
                                                 unsigned long target_freep)
{
    if (!cache->nfreeslabs)
        return 0;

    unsigned long freed = 0;

    list_for_every_safe (&cache->free_slabs)
    {
        auto s = container_of(l, struct slab, slab_list_node);
        if (freed >= target_freep)
            break;
        size_t slab_pages = s->size >> PAGE_SHIFT;
        kmem_cache_free_slab(s);
        cache->nfreeslabs--;
        freed += slab_pages;
    }

    ASSERT_SLAB_COUNT(cache);
    return freed;
}

/**
 * @brief Shrink a slab cache by a number of pages
 *
 * @param cache Cache to shrink
 * @param target_freep Target free pages
 * @return Freed pages
 */
static unsigned long kmem_cache_shrink(struct slab_cache *cache, unsigned long target_freep)
{
    scoped_lock g{cache->lock};

    sched_disable_preempt();

    struct slab_rendezvous rndvz;
    kmem_slab_freeze_start(&rndvz);
    kmem_cache_shrink_pcpu_all(cache);
    kmem_slab_freeze_end(&rndvz);
    sched_enable_preempt();

    ASSERT_SLAB_COUNT(cache);
    unsigned long freed = kmem_cache_release_free_all(cache, target_freep);
    kmem_slab_freeze_wait(&rndvz);
    return freed;
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
#ifdef CONFIG_KASAN
    // Flushing the KASAN quarantine is important as to let objects go back to the slabs
    kasan_flush_quarantine();
#endif
    kmem_cache_shrink(cache, ULONG_MAX);
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

#ifdef CONFIG_KASAN
    // Flushing the KASAN quarantine is important as to let objects go back to the slabs
    kasan_flush_quarantine();
#endif

    {
        scoped_mutex g{cache_list_lock};
        kmem_cache_shrink(cache, ULONG_MAX);

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
        unsigned int flags = KMEM_CACHE_VMALLOC;
#if 0
        // TODO: Toggling VMALLOC only for larger sizes is not working well...
        // at least for will-it-scale/page_fault1, it results in major performance regressions.
        // Is this a TLB issue? Maybe?
        if (i >= 16)
            flags |= KMEM_CACHE_VMALLOC;
#endif
        snprintf(kmalloc_cache_names[i], 20, "kmalloc-%zu", size);
        kmalloc_caches[i] = kmem_cache_create(kmalloc_cache_names[i], size, 0, flags, nullptr);
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

    void *ret = kmem_cache_alloc(kmalloc_caches[order], flags);

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
    return kmalloc(size, GFP_ATOMIC);
}

void free(void *ptr)
{
    return kfree(ptr);
}

void *kcalloc(size_t nr, size_t size, int flags)
{
    if (array_overflows(nr, size))
        return errno = EOVERFLOW, nullptr;

    const auto len = nr * size;

    void *ptr = kmalloc(len, flags);
    if (!ptr) [[unlikely]]
        return errno = ENOMEM, nullptr;

    memset(ptr, 0, len);
    return ptr;
}

void *calloc(size_t nr, size_t size)
{
    return kcalloc(nr, size, GFP_ATOMIC);
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
    __memcpy(newbuf, ptr, old_slab->cache->objsize);
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
    scoped_lock g{slab->cache->lock};
    kmem_free_to_slab(slab->cache, slab, ptr);
}

static void stack_trace_print(unsigned long *entries, unsigned long nr)
{
    printk("\n");
    for (unsigned long i = 0; i < nr; i++)
    {
        char sym[SYM_SYMBOLIZE_BUFSIZ];
        int st = sym_symbolize((void *) entries[i], cul::slice<char>{sym, sizeof(sym)});
        if (st < 0)
            break;
        printk("\t%s\n", sym);
    }

    printk("\n");
}

/**
 * @brief Print KASAN-relevant info for this mem-slab
 *
 * @param mem Pointer to the memory
 * @param slab Pointer to its slab
 */
void kmem_cache_print_slab_info_kasan(void *mem, struct slab *slab)
{
    slab_cache *cache = slab->cache;
    const char *status =
        (slab->active_objects == 0 ? "free"
                                   : (slab->active_objects == slab->nobjects ? "full" : "partial"));

    printk("%p is apart of cache %s slab %p - slab status %s\n", mem, cache->name, slab, status);

    // Walk through the slab and find this object's starting redzone
    const size_t nr_objects = slab->nobjects;
    u8 *ptr = (u8 *) slab->start;

    struct kasan_slab_obj_info *info = nullptr;
    for (size_t i = 0; i < nr_objects; i++, ptr += cache->objsize + cache->redzone)
    {
        auto eff_size = cache->objsize + cache->redzone;
        if (ptr <= (u8 *) mem && ptr + eff_size > (u8 *) mem)
        {
            info = (struct kasan_slab_obj_info *) ptr;
            break;
        }
    }

    if (!info)
    {
        printk("%p is not a pointer to a valid object in the slab!\n", ptr);
        return;
    }

    printk("%p was last allocated by: ", mem);

    if (info->alloc_stack == DEPOT_STACK_HANDLE_INVALID)
        printk("<no stack trace available>\n");
    else
    {
        struct stacktrace *trace = stackdepot_from_handle(info->alloc_stack);
        stack_trace_print(trace->entries, trace->size);
    }

    printk("%p was last freed by: ", mem);

    if (info->free_stack == DEPOT_STACK_HANDLE_INVALID)
        printk("<no stack trace available>\n");
    else
    {
        struct stacktrace *trace = stackdepot_from_handle(info->free_stack);
        stack_trace_print(trace->entries, trace->size);
    }

    // Pad "Memory information: " for the next info dump
    printk("                    ");
}

#endif

/**
 * @brief Shrink caches in order to free pages
 *
 * @param target_freep Target free pages
 */
void slab_shrink_caches(unsigned long target_freep)
{
    scoped_mutex g{cache_list_lock};
    struct slab_rendezvous rndvz;
    sched_disable_preempt();
    kmem_slab_freeze_start(&rndvz);
    sched_enable_preempt();

    list_for_every (&cache_list)
    {
        struct slab_cache *cache = container_of(l, struct slab_cache, cache_list_node);
        /* Note: We need to try_lock the slab, as a slab freeze can have CPUs suspended
         * mid-allocation, either in the pcpu caches or even holding the cache lock. As such, we
         * try_lock and skip the cache if we fail to grab it. */
        if (!spin_try_lock(&cache->lock))
        {
            kmem_cache_shrink_pcpu_all(cache);
            spin_unlock(&cache->lock);
        }
    }

    kmem_slab_freeze_end(&rndvz);

    list_for_every (&cache_list)
    {
        struct slab_cache *cache = container_of(l, struct slab_cache, cache_list_node);
        unsigned long freed = 0;
        /* The limitation above does not apply, because caches have been unfrozen. */
        scoped_lock g{cache->lock};
        freed = kmem_cache_release_free_all(cache, target_freep);
        if (freed >= target_freep)
            break;
        target_freep -= freed;
    }

    kmem_slab_freeze_wait(&rndvz);
}
