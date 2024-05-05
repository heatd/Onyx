/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <onyx/copy.h>
#include <onyx/init.h>
#include <onyx/mm/reclaim.h>
#include <onyx/modules.h>
#include <onyx/page.h>
#include <onyx/pagecache.h>
#include <onyx/panic.h>
#include <onyx/spinlock.h>
#include <onyx/stackdepot.h>
#include <onyx/utils.h>
#include <onyx/vm.h>
#include <onyx/wait_queue.h>

#include <uapi/memstat.h>

#include <onyx/atomic.hpp>

/**
 * @brief min_free_kbytes similar to linux, used to scale zone watermarks.
 *
 */
static unsigned long min_free_kbytes = 1024;
size_t page_memory_size;
cul::atomic_size_t nr_global_pages;

__always_inline unsigned long pow2(unsigned int exp)
{
    return (1UL << (unsigned long) exp);
}

#define PAGEALLOC_NR_ORDERS 14

#define MAX_PCPU_PAGES    1024
#define PCPU_REFILL_PAGES 512
#define PCPU_REFILL_ORDER 9

struct page_pcpu_data
{
    struct list_head page_list;
    unsigned long nr_pages{0};
    unsigned long nr_fast_path{0};
    unsigned long nr_slow_path{0};
    unsigned long nr_queue_reclaims{0};
    long pagestats[PAGE_STATS_MAX];

    constexpr page_pcpu_data()
    {
        INIT_LIST_HEAD(&page_list);
        for (auto &stat : pagestats)
            stat = 0;
    }

    /**
     * @brief Allocate from pcpu state.
     * IRQs must be disabled
     * @return Allocated struct page, or nullptr
     */
    __attribute__((always_inline)) struct page *alloc()
    {
        if (nr_pages == 0) [[unlikely]]
            return nullptr;

        struct page *page = container_of(list_first_element(&page_list), struct page,
                                         page_allocator_node.list_node);
        list_remove(&page->page_allocator_node.list_node);

        nr_pages--;

        return page;
    }

    /**
     * @brief Free to pcpu state
     * IRQs must be disabled
     * @param page Page to free
     */
    __attribute__((always_inline)) void free(struct page *page)
    {
        list_add_tail(&page->page_allocator_node.list_node, &page_list);
        nr_pages++;
    }

} __align_cache;

struct page_zone
{
    const char *name;
    unsigned long start;
    unsigned long end;
    unsigned long min_watermark;
    unsigned long low_watermark;
    unsigned long high_watermark;
    struct list_head pages[PAGEALLOC_NR_ORDERS];
    unsigned long total_pages;
    long used_pages;
    unsigned long splits;
    unsigned long merges;
    spinlock lock;
    page_pcpu_data pcpu[CONFIG_SMP_NR_CPUS] __align_cache;
};

__always_inline bool page_is_buddy(page *page)
{
    return page->flags == PAGE_BUDDY;
}

__always_inline void page_debuddy(page *page)
{
    page->priv = 0;
    page->flags &= ~PAGE_BUDDY;
}

__always_inline void page_make_buddy(page *page, unsigned int order)
{
    page->priv = order;
    page->flags |= PAGE_BUDDY;
}

static struct pagedaemon_data
{
    /**
     * @brief Order we tried to allocate. In case multiple allocations are in progress, this is set
     * to the max order.
     */
    int order;
    /**
     * @brief Max attempt at reclaim. Desperate times call for desperate measures.
     */
    int attempt;
    struct wait_queue paged_queue;
    struct wait_queue paged_waiters_queue;
    unsigned long reclaim_seq;
    unsigned long request_seq;
    thread_t *paged_thread;
} paged_data;

static unsigned long wake_up_pagedaemon(int order, int attempt = -1)
{
    if (paged_data.order < order)
        __atomic_store_n(&paged_data.order, order, __ATOMIC_RELAXED);
    if (paged_data.attempt < attempt)
        __atomic_store_n(&paged_data.attempt, attempt, __ATOMIC_RELAXED);
    unsigned long our_seq = __atomic_add_fetch(&paged_data.request_seq, 1, __ATOMIC_RELEASE);
    wait_queue_wake_all(&paged_data.paged_queue);
    return our_seq;
}

static bool page_has_low_memory();

#define PAGEDAEMON_THROTTLE_MS 5000

static void pagedaemon(void * /*arg*/)
{
    /* This thread is responsible for asynchronous reclamation of memory in low memory conditions.
     * It is woken up when a zone reaches the low watermark, and sleeps after every zone reached the
     * high watermark.
     */
    for (;;)
    {
        wait_for_event(&paged_data.paged_queue, paged_data.request_seq > paged_data.reclaim_seq);

        int i = 0;
        if (!page_has_low_memory())
            goto wake;
        /* Attempt to do reclaim a handful of times */
        for (i = 0; i < 4; i++)
        {
            struct reclaim_data data;
            data.attempt = paged_data.attempt + i;
            data.failed_order = paged_data.order;
            data.gfp_flags = GFP_KERNEL;
            data.mode = RECLAIM_MODE_PAGEDAEMON;
            int st = page_do_reclaim(&data);

            if (st == 0)
                break;
        }

    wake:
        __atomic_add_fetch(&paged_data.reclaim_seq, 1, __ATOMIC_RELEASE);
        /* Wake up anyone that may potentially be waiting for us */
        wait_queue_wake_all(&paged_data.paged_waiters_queue);

        if (i == 4)
        {
            /* Chill for some seconds, try again later */
            sched_sleep_ms(PAGEDAEMON_THROTTLE_MS);
        }
    }
}

static void do_direct_reclaim(int order, int attempt, unsigned int gfp_flags)
{
    struct reclaim_data data;
    data.attempt = attempt;
    data.failed_order = order;
    data.gfp_flags = gfp_flags;
    data.mode = RECLAIM_MODE_DIRECT;
    page_do_reclaim(&data);
}

static struct page *page_zone_alloc_core(page_zone *zone, unsigned int gfp_flags,
                                         unsigned int order)
{
    /* *zone->lock held*, irqs disabled */
    unsigned long nr_pgs = pow2(order);
    unsigned int i;
    struct page *pages = nullptr;
    bool no_remove = false;
    bool may_use_reserves = gfp_flags & __GFP_ATOMIC;
    unsigned long free_pages = zone->total_pages - zone->used_pages;

    if (free_pages < nr_pgs)
        return nullptr;

    if (!may_use_reserves && zone->min_watermark > free_pages - nr_pgs)
        return nullptr;

    if (!list_is_empty(&zone->pages[order])) [[likely]]
    {
        pages = container_of(list_first_element(&zone->pages[order]), struct page,
                             page_allocator_node.list_node);
        CHECK(page_is_buddy(pages));
        page_debuddy(pages);
        goto out;
    }

    /* Ok, this order has no pages, lets try to split upper orders */
    for (i = order + 1; i < PAGEALLOC_NR_ORDERS; i++)
    {
        if (!list_is_empty(&zone->pages[i]))
        {
            pages = container_of(list_first_element(&zone->pages[i]), struct page,
                                 page_allocator_node.list_node);
            CHECK(pages->flags == PAGE_BUDDY);
            page_debuddy(pages);
            list_remove(&pages->page_allocator_node.list_node);
            // No need to remove it later on, we've already done it
            no_remove = true;
            zone->splits++;
            break;
        }
    }

    if (!pages)
        return nullptr;

    // Now that we have a higher-order block, lets feed it back down
    while (i-- != order)
    {
        // Feed the second half back to the lower order, keep the first half
        // This first half will then be either further fed back, or kept
        size_t nr_pages = pow2(i);

        struct page *p2 = pages + nr_pages;
        list_add_tail(&p2->page_allocator_node.list_node, &zone->pages[i]);
        DCHECK(!page_is_buddy(p2));
        page_make_buddy(p2, i);
    }

out:
    DCHECK(!page_is_buddy(pages));
    pages->flags = 0;
    if (!no_remove)
        list_remove(&pages->page_allocator_node.list_node);
    zone->used_pages += nr_pgs;

    if (gfp_flags & __GFP_WAKE_PAGEDAEMON &&
        zone->total_pages - zone->used_pages <= zone->low_watermark)
    {
        /* Memory is getting low in this zone, preemptively wake up pagedaemon */
        wake_up_pagedaemon(0);
    }

    return pages;
}

static struct page *page_zone_refill_pcpu(struct page_zone *zone, unsigned int gfp_flags,
                                          page_pcpu_data *queue)
{
    unsigned int pages_collected = 0;
    struct page *ret = nullptr;
    scoped_lock<spinlock, true> g{zone->lock};

    __atomic_add_fetch(&queue->nr_slow_path, 1, __ATOMIC_RELAXED);

    /* Let's go through all the orders from the optimal (PCPU_REFILL_ORDER) down to 0 and attempt to
     * get the number of pages we do desire.
     */
    for (int order = PCPU_REFILL_ORDER; order >= 0; order--)
    {
        const unsigned long order_nr_pages = pow2(order);

        while (pages_collected < PCPU_REFILL_PAGES)
        {
            unsigned int i = 0;

            /* If we have our allocation, do *not* use our reserves */
            if (ret)
                gfp_flags &= ~__GFP_ATOMIC;
            struct page *pages = page_zone_alloc_core(zone, gfp_flags, order);
            if (!pages)
                break;

            pages_collected += order_nr_pages;

            if (!ret)
            {
                // Take the first page for the ret
                ret = pages;
                i++;
            }

            for (; i < order_nr_pages; i++)
            {
                struct page *p = pages + i;
                list_add_tail(&p->page_allocator_node.list_node, &queue->page_list);
                queue->nr_pages++;
            }
        }
    }

    return ret;
}

struct page *page_zone_alloc(struct page_zone *zone, unsigned int gfp_flags, unsigned int order)
{
    if (order == 0) [[likely]]
    {
        // Let's use pcpu caching for order-0 pages
        auto flags = irq_save_and_disable();
        page_pcpu_data *queue = &zone->pcpu[get_cpu_nr()];
        auto pages = queue->alloc();

        /* gfp_flags note: page_zone_refill_pcpu is careful enough to not use atomic reserves for
         * pcpu refilling, by looking at the watermarks when doing allocation. We obviously do not
         * want to exhaust memory reserves filling a silly pcpu cache.
         */
        if (!pages) [[unlikely]]
            pages = page_zone_refill_pcpu(zone, gfp_flags, queue);
        else
            __atomic_add_fetch(&queue->nr_fast_path, 1, __ATOMIC_RELAXED);

        irq_restore(flags);

        return pages;
    }

    unsigned long nr_pgs = pow2(order);

    if (zone->total_pages - zone->used_pages < nr_pgs)
        return nullptr;

    scoped_lock<spinlock, true> g{zone->lock};

    return page_zone_alloc_core(zone, gfp_flags, order);
}

static void page_zone_add(unsigned long start, unsigned int order, struct page_zone *zone)
{
    scoped_lock g{zone->lock};

    auto nr_pages = pow2(order);
    for (unsigned long i = 0; i < nr_pages; i++)
    {
        // Initalize all struct pages
        page_add_page((void *) (start + (i << PAGE_SHIFT)));
    }

    zone->total_pages += nr_pages;
    struct page *headpage = phys_to_page(start);
    page_make_buddy(headpage, order);
    list_add_tail(&headpage->page_allocator_node.list_node, &zone->pages[order]);
}

void page_zone_add_region(unsigned long start, unsigned long nrpgs, struct page_zone *zone)
{
    CHECK(start != 0);
    CHECK((start & (PAGE_SIZE - 1)) == 0);
    while (nrpgs)
    {
        unsigned long alignment = __builtin_ctzl(start);
        unsigned long order = cul::clamp(alignment - PAGE_SHIFT, PAGEALLOC_NR_ORDERS - 1ul);
        unsigned long region_pgs = 0;

        for (long i = order; i >= 0; i--)
        {
            region_pgs = pow2(i);
            if (nrpgs < region_pgs)
                continue;

#ifdef CONFIG_PAGEALLOC_DEBUG_BUDDY
            printf("page_zone: adding [%lx, %lx] (order-%lu)\n", start,
                   start + (1UL << (i + PAGE_SHIFT)) - 1, i);
#endif
            page_zone_add(start, i, zone);
            break;
        }

        DCHECK(region_pgs != 0);

        nrpgs -= region_pgs;
        start += region_pgs << PAGE_SHIFT;
    }
}

size_t page_zone_get_used_pages(struct page_zone *zone)
{
    scoped_lock<spinlock, true> g{zone->lock};
    return zone->used_pages;
}

__always_inline struct page *get_buddy(struct page *page, unsigned int order, page_zone *zone)
{
    unsigned long pfn = page_to_pfn(page);
    unsigned long pfn2 = pfn ^ (1UL << order);

    // Check if we can indeed merge with a buddy. if so
    // 1) the buddy is not past maxpfn (phys_to_page_mayfail)
    // 2) the buddy is free and the same order as us
    // 3) the buddy is in the same zone

    struct page *p = phys_to_page_mayfail(pfn2 << PAGE_SHIFT);
    if (!p) [[unlikely]]
        return nullptr;
    if (!(p->flags & PAGE_BUDDY) || p->priv != order)
        return nullptr;
    if (pfn2 < zone->start || pfn2 > zone->end)
        return nullptr;
    return p;
}

static void page_zone_free_core(page_zone *zone, struct page *page, unsigned int order)
{
    /* *zone->lock held, irqs disabled* */
    zone->used_pages -= pow2(order);

    for (; order < PAGEALLOC_NR_ORDERS - 1; order++)
    {
        // Check if buddy is free
        struct page *buddy = get_buddy(page, order, zone);
        if (!buddy) [[likely]]
            break;

        // Great, it's free, let's merge. The head will be what we're trying to insert.
        page_debuddy(buddy);
        list_remove(&buddy->page_allocator_node.list_node);
        struct page *to = buddy < page ? buddy : page;
        page = to;
        zone->merges++;
    }

    // Now, insert the head into the order. Lets add to the head as this page
    // is likely cache-hot.
    page_make_buddy(page, order);
    list_add(&page->page_allocator_node.list_node, &zone->pages[order]);
}

static void page_zone_release_pcpu(page_zone *zone, page_pcpu_data *queue)
{
    scoped_lock<spinlock, true> g{zone->lock};
    while (queue->nr_pages > MAX_PCPU_PAGES / 2)
    {
        struct page *p = container_of(list_first_element(&queue->page_list), struct page,
                                      page_allocator_node.list_node);
        list_remove(&p->page_allocator_node.list_node);
        queue->nr_pages--;
        page_zone_free_core(zone, p, 0);
    }
}

static void page_zone_drain_pcpu_local(page_zone *zone)
{
    /* Note: irqs are off */
    scoped_lock<spinlock, true> g{zone->lock};
    page_pcpu_data *queue = &zone->pcpu[get_cpu_nr()];
    while (queue->nr_pages > 0)
    {
        struct page *p = container_of(list_first_element(&queue->page_list), struct page,
                                      page_allocator_node.list_node);
        list_remove(&p->page_allocator_node.list_node);
        queue->nr_pages--;

        page_zone_free_core(zone, p, 0);
    }
    queue->nr_queue_reclaims++;
}

void page_zone_free(page_zone *zone, struct page *page, unsigned int order)
{
    if (order == 0) [[likely]]
    {
        // Lets release this page into the pcpu queue
        auto flags = irq_save_and_disable();
        page_pcpu_data *queue = &zone->pcpu[get_cpu_nr()];

        queue->free(page);

        if (queue->nr_pages > MAX_PCPU_PAGES) [[unlikely]]
        {
            __atomic_add_fetch(&queue->nr_queue_reclaims, 1, __ATOMIC_RELAXED);
            page_zone_release_pcpu(zone, queue);
        }

        irq_restore(flags);
        return;
    }

    scoped_lock<spinlock, true> g{zone->lock};
    page_zone_free_core(zone, page, order);
}

constexpr void page_zone_init(page_zone *zone, const char *name, unsigned long start,
                              unsigned long end)
{
    zone->name = name;
    zone->start = start;
    zone->end = end;
    zone->high_watermark = zone->min_watermark = zone->low_watermark = 0;
    spinlock_init(&zone->lock);
    for (auto &order : zone->pages)
    {
        INIT_LIST_HEAD(&order);
    }

    zone->total_pages = 0;
    zone->used_pages = 0;
    zone->merges = zone->splits = 0;
}

class page_node
{
private:
    struct spinlock node_lock;
    struct list_head cpu_list_node;
    unsigned long used_pages{0};
    unsigned long total_pages{0};
    struct page_zone zones[NR_ZONES];

public:
    struct page_zone *pick_zone(unsigned long page);

    constexpr page_node() : node_lock{}, cpu_list_node{}
    {
        spinlock_init(&node_lock);
        page_zone_init(&zones[0], "DMA32", 0, UINT32_MAX);
        page_zone_init(&zones[1], "Normal", (u64) UINT32_MAX + 1, UINT64_MAX);
    }

    void init()
    {
        INIT_LIST_HEAD(&cpu_list_node);
    }

    void add_region(unsigned long base, size_t size);
    struct page *alloc_order(unsigned int order, unsigned long flags);
    struct page *allocate_pages(unsigned long nr_pages, unsigned long flags);
    struct page *alloc_page(unsigned long flags);
    void free_page(struct page *p);

    template <typename Callable>
    bool for_every_zone(Callable c)
    {
        for (auto &zone : zones)
        {
            if (!c(&zone))
                return false;
        }

        return true;
    }
};

static bool page_is_initialized = false;

page_node main_node;

struct page_zone *page_node::pick_zone(unsigned long page)
{
    if (page < UINT32_MAX)
        return &zones[ZONE_DMA32];
    return &zones[ZONE_NORMAL];
}

void page_node::add_region(uintptr_t base, size_t size)
{
    if (size <= PAGE_SIZE)
        return;

    if (base & (PAGE_SIZE - 1))
        base = (unsigned long) page_align_up((void *) base);

    size &= -PAGE_SIZE;

    printf("pagealloc: Adding region %lx, %016lx\n", base, base + size - 1);

    while (size)
    {
        // Check what zone we want to add stuff to
        struct page_zone *zone = pick_zone(base);

        unsigned long start = base;
        unsigned long end = cul::clamp(start + size, zone->end) + 1;
        unsigned long nr_pages = (end - start) >> PAGE_SHIFT;
        printf("pagealloc: Adding [%016lx, %016lx] to zone %s\n", start, end - 1, zone->name);
        page_zone_add_region(start, nr_pages, zone);
        nr_global_pages.add_fetch(nr_pages, mem_order::release);
        start = end;
        size -= nr_pages << PAGE_SHIFT;
    }
}

template <typename Callable>
bool for_every_node(Callable c)
{
    return c(main_node);
}

static bool page_has_low_memory()
{
    bool result = false;
    for_every_node([&](page_node &node) -> bool {
        return node.for_every_zone([&](page_zone *zone) -> bool {
            unsigned long freep = zone->total_pages - zone->used_pages;
            result = result ? true : freep < zone->low_watermark;
            return !result; /* if we found a low mem zone, break the iteration */
        });
    });
    return result;
}

/**
 * @brief Calculate the number of pages under the high watermark in every zone, for every node
 *
 * @return Number of pages under the high watermark
 */
unsigned long pages_under_high_watermark()
{
    unsigned long result = 0;
    for_every_node([&](page_node &node) -> bool {
        return node.for_every_zone([&](page_zone *zone) -> bool {
            unsigned long freep = zone->total_pages - zone->used_pages;

            if (freep <= zone->low_watermark)
                result += zone->high_watermark - freep;
            return false;
        });
    });
    return result;
}

static void page_set_watermarks()
{
    /* Set each watermark scaled to the zone's size */
    for_every_node([&](page_node &node) -> bool {
        return node.for_every_zone([&](page_zone *zone) -> bool {
            zone->min_watermark =
                (zone->total_pages * min_free_kbytes / (page_memory_size / 1024)) /
                (PAGE_SIZE / 1024);
            zone->low_watermark = zone->min_watermark * 8;
            zone->high_watermark = zone->low_watermark * 2;
            printf("page: zone %s\n", zone->name);
            printf("  min watermark %lu\n"
                   "  low watermark %lu\n"
                   "  high watermark %lu\n"
                   "  total pages %lu\n",
                   zone->min_watermark, zone->low_watermark, zone->high_watermark,
                   zone->total_pages);
            return true;
        });
    });
}

void page_init(size_t memory_size, unsigned long maxpfn)
{
    main_node.init();

    printf("page: Memory size: %lu\n", memory_size);
    page_memory_size = memory_size;

    size_t needed_memory = maxpfn * sizeof(struct page);
    void *ptr = alloc_boot_page(vm_size_to_pages(needed_memory), 0);
    if (!ptr)
    {
        halt();
    }

    __kbrk(PHYS_TO_VIRT(ptr), (void *) ((unsigned long) PHYS_TO_VIRT(ptr) + needed_memory));
    page_allocate_pagemap(maxpfn);

    for_every_phys_region([](unsigned long start, size_t size) {
        /* page_add_region can't return an error value since it halts
         * on failure
         */
        main_node.add_region(start, size);
    });

    min_free_kbytes =
        cul::max(min_free_kbytes, page_memory_size / 1024 / 60 /* 1.6% of the whole memory */);

    page_set_watermarks();

    page_is_initialized = true;
}

size_t page_get_used_pages()
{
    unsigned long used_pages = 0;
    for_every_node([&](page_node &node) -> bool {
        return node.for_every_zone([&](page_zone *zone) -> bool {
            used_pages += page_zone_get_used_pages(zone);
            return true;
        });
    });

    return used_pages;
}

void page_get_stats(struct memstat *m)
{
    unsigned long pagestats[PAGE_STATS_MAX];
    page_accumulate_stats(pagestats);
    m->total_pages = nr_global_pages.load(mem_order::acquire);
    m->allocated_pages = page_get_used_pages();
    m->page_cache_pages = pagestats[NR_FILE];
    m->kernel_heap_pages = 0;
}

extern unsigned char kernel_end;

void *kernel_break = &kernel_end;
static void *kernel_break_limit = NULL;

__attribute__((malloc)) void *__ksbrk(long inc)
{
    void *ret = kernel_break;
    kernel_break = (char *) kernel_break + inc;

    assert((unsigned long) kernel_break <= (unsigned long) kernel_break_limit);
    return ret;
}

void __kbrk(void *break_, void *kbrk_limit)
{
    kernel_break = break_;
    kernel_break_limit = kbrk_limit;
}

void free_pages(struct page *pages)
{
    assert(pages != NULL);
    struct page *next = NULL;

    for (struct page *p = pages; p != NULL; p = next)
    {
        next = p->next_un.next_allocation;
        free_page(p);
    }
}

static void stack_trace_print(u32 stackdepot_handle)
{
    if (stackdepot_handle == DEPOT_STACK_HANDLE_INVALID)
    {
        printk("<Information not available>\n");
        return;
    }

    struct stacktrace *trace = stackdepot_from_handle(stackdepot_handle);
    printk("\n");
    for (unsigned long i = 0; i < trace->size; i++)
    {
        char sym[SYM_SYMBOLIZE_BUFSIZ];
        int st = sym_symbolize((void *) trace->entries[i], cul::slice<char>{sym, sizeof(sym)});
        if (st < 0)
            break;
        printk("\t%s\n", sym);
    }

    printk("\n");
}

#ifdef CONFIG_PAGE_OWNER
static void dump_page_ownership(struct page *page)
{
    printk("page %p last locked by: ", page);
    stack_trace_print(page->last_lock);
    printk("        last unlocked by: ");
    stack_trace_print(page->last_unlock);
    printk("        last owned by: ");
    stack_trace_print(page->last_owner);
    printk("        last freed by: ");
    stack_trace_print(page->last_free);
}
#endif

static void debug_page(const char *message, struct page *page)
{
    panic_start();
    printk("Assertion '%s' failed on page %p (pfn %lu)", message, page, page_to_pfn(page));
#ifdef CONFIG_PAGE_OWNER
    dump_page_ownership(page);
#endif
}

#define PAGE_CHECK(cond, page) \
    if (!(cond))               \
    {                          \
        debug_page(#cond, p);  \
        panic(#cond);          \
    }

void free_page(struct page *p)
{
    assert(p != NULL);
    PAGE_CHECK(p->ref != 0, p);

    if (__page_unref(p) == 0)
    {
        p->next_un.next_allocation = NULL;
        main_node.free_page(p);
        // printf("free pages %p, %p\n", page_to_phys(p), __builtin_return_address(0));
    }
#if 0
	else
	{
		printf("unref pages %p(refs %lu), %p\n", page_to_phys(p), p->ref, __builtin_return_address(0));
	}
#endif
}

struct page *page_node::allocate_pages(size_t nr_pgs, unsigned long flags)
{
    struct page *plist = NULL;
    struct page *ptail = NULL;

    for (size_t i = 0; i < nr_pgs; i++)
    {
        struct page *p = alloc_order(0, flags);

        if (!p)
        {
            if (plist)
                free_page_list(plist);

            return nullptr;
        }

        if (!plist)
        {
            plist = ptail = p;
        }
        else
        {
            ptail->next_un.next_allocation = p;
            ptail = p;
        }
    }

    // printf("alloc pages %lu = %p, %p\n", nr_pgs, page_to_phys(plist),
    // __builtin_return_address(0));

    return plist;
}

__always_inline void prepare_pages_after_alloc(struct page *page, unsigned int order,
                                               unsigned long flags)
{
    struct page *last = nullptr;

    auto pages = pow2(order);

    if (page_should_zero(flags))
    {
        memset(PAGE_TO_VIRT(page), 0, 1UL << (order + PAGE_SHIFT));
    }

    for (; pages != 0; pages--, last = page++)
    {
        __atomic_store_n(&page->ref, 1, __ATOMIC_RELEASE);
        page->flags = 0;
        page->priv = 0;
        page->next_un.next_allocation = nullptr;
        if (last)
            last->next_un.next_allocation = page;
#ifdef CONFIG_PAGE_OWNER
        if (!(flags & __GFP_NO_INSTRUMENT))
            page_owner_owned(page);
#endif
    }
}

#define PAGE_ALLOC_MAX_RECLAIM_ATTEMPT 5

struct page *page_node::alloc_order(unsigned int order, unsigned long flags)
{
    struct page *page = nullptr;
    unsigned int attempt = 0;

    for (;;)
    {
        if (attempt == PAGE_ALLOC_MAX_RECLAIM_ATTEMPT)
        {
            /* Avoid locking up the system by just returning NULL */
            return nullptr;
        }

        int zone = ZONE_NORMAL;

        if (flags & PAGE_ALLOC_4GB_LIMIT)
            zone = ZONE_DMA32;

        while (zone >= 0)
        {
            page = page_zone_alloc(&zones[zone], flags, order);

            if (page)
                goto out;
            zone--;
        }

        if (likely(page))
            break;

        if (flags & __GFP_DIRECT_RECLAIM)
            do_direct_reclaim(order, attempt, flags);
        else if (flags & __GFP_WAKE_PAGEDAEMON)
        {
            unsigned long cur_seq = wake_up_pagedaemon(order, attempt);
            if (!(flags & __GFP_ATOMIC))
            {
                wait_for_event(&paged_data.paged_waiters_queue, cur_seq < paged_data.reclaim_seq);
            }
            else
                return nullptr; /* Since __GFP_ATOMIC cannot wait here, we simply fail. */
        }
        else
            return nullptr; /* No reclaim, just fail */

        attempt++;
    }

out:
    prepare_pages_after_alloc(page, order, flags);

    return page;
}

struct page *alloc_pages(unsigned int order, unsigned long flags)
{
    auto &node = main_node;
    return node.alloc_order(order, flags);
}

void __reclaim_page(struct page *new_page)
{
    nr_global_pages.add_fetch(1, mem_order::release);
    auto &node = main_node;
    node.add_region((unsigned long) page_to_phys(new_page), PAGE_SIZE);
}

void page_node::free_page(struct page *p)
{
    CHECK(!(p->flags & (PAGE_FLAG_WRITEBACK | PAGE_FLAG_LOCKED)));
#ifdef CONFIG_PAGE_OWNER
    page_owner_freed(p);
#endif

    unsigned long cpu_flags = spin_lock_irqsave(&node_lock);
    /* Reset the page */
    p->flags = 0;
    p->owner = nullptr;
    p->pageoff = 0;
    p->next_un.next_allocation = nullptr;
    p->ref = 0;

    /* Add it at the beginning since it might be fresh in the cache */
    // list_add(&p->page_allocator_node.list_node, &page_list);

    struct page_zone *z = pick_zone((unsigned long) page_to_phys(p));
    // XXX Free higher order stuff directly
    page_zone_free(z, p, 0);

    spin_unlock_irqrestore(&node_lock, cpu_flags);
}

/**
 * @brief Allocate a list of pages
 *
 * @param nr_pages Number of pages to allocate
 * @param gfp_flags GFP flags
 * @return List of struct pages linked by next_un.next_allocation, or NULL
 */
struct page *alloc_page_list(size_t nr_pages, unsigned int gfp_flags)
{
    return main_node.allocate_pages(nr_pages, gfp_flags);
}

/**
 * @brief Free a list of pages
 *
 * @param pages List of linked struct pages as retrieved from alloc_page_list
 */
void free_page_list(struct page *pages)
{
    free_pages(pages);
}

static void page_drain_pcpu_local()
{
    for_every_node([](page_node &node) -> bool {
        return node.for_every_zone([](page_zone *zone) -> bool {
            page_zone_drain_pcpu_local(zone);
            return true;
        });
    });
}

/**
 * @brief Drain pages from all zones' pcpu caches
 *
 */
void page_drain_pcpu()
{
    smp::sync_call_with_local([](void *ctx) { page_drain_pcpu_local(); }, nullptr, cpumask::all(),
                              [](void *ctx) { page_drain_pcpu_local(); }, nullptr);
}

static void setup_pagedaemon()
{
    paged_data.paged_thread = sched_create_thread(pagedaemon, THREAD_KERNEL, nullptr);
    CHECK(paged_data.paged_thread != nullptr);
    paged_data.paged_thread->priority = SCHED_PRIO_VERY_HIGH - 2;
    sched_start_thread(paged_data.paged_thread);
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(setup_pagedaemon);

static struct page_zone *page_to_zone(struct page *page)
{
    return main_node.pick_zone((unsigned long) page_to_phys(page));
}

void inc_page_stat(struct page *page, enum page_stat stat)
{
    struct page_zone *zone = page_to_zone(page);
    sched_disable_preempt();
    zone->pcpu[get_cpu_nr()].pagestats[stat]++;
    sched_enable_preempt();
}

void dec_page_stat(struct page *page, enum page_stat stat)
{
    struct page_zone *zone = page_to_zone(page);
    sched_disable_preempt();
    zone->pcpu[get_cpu_nr()].pagestats[stat]--;
    sched_enable_preempt();
}

void page_accumulate_stats(unsigned long pages[PAGE_STATS_MAX])
{
    for (unsigned int i = 0; i < PAGE_STATS_MAX; i++)
        pages[i] = 0;

    for_every_node([&pages](page_node &node) {
        node.for_every_zone([&pages](struct page_zone *zone) {
            for (auto &pcpu : zone->pcpu)
            {
                for (unsigned int j = 0; j < PAGE_STATS_MAX; j++)
                    pages[j] += pcpu.pagestats[j];
            }

            return true;
        });

        return true;
    });
}
