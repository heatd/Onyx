/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_PAGE_H
#define _ONYX_PAGE_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/atomic.h>
#include <onyx/compiler.h>
#include <onyx/list.h>
#include <onyx/lock_annotations.h>
#include <onyx/ref.h>
#include <onyx/spinlock.h>
#include <onyx/vm.h>
#include <onyx/wait.h>

__BEGIN_CDECLS

/* The default physical allocator is the buddy allocator */
#if defined(__x86_64__) || defined(__riscv) || defined(__aarch64__)

#include <platform/page.h>

#define PAGES_PER_AREA 512
#define MAX_ORDER      11
#define HUGE_PAGE_SIZE 0x200000

#define DMA_UPPER_LIMIT   (void *) 0x1000000
#define HIGH_MEM_FLOOR    DMA_UPPER_LIMIT
#define HIGH_MEM_LIMIT    (void *) 0xFFFFFFFF
#define HIGH_MEM_64_FLOOR HIGH_MEM_LIMIT
#define HIGH_MEM_64_LIMIT (void *) -1

#else
#error "Define PAGES_PER_AREA and/or MAX_ORDER"
#endif

#define NR_ZONES 2

#define ZONE_DMA32          0
#define ZONE_NORMAL         1
#define IS_HUGE_ALIGNED(x)  (((unsigned long) x % HUGE_PAGE_SIZE) ? 0 : 1)
#define IS_DMA_PTR(x)       x < DMA_UPPER_LIMIT
#define IS_HIGHMEM_PTR(x)   x > HIGH_MEM_FLOOR &&x < HIGH_MEM_LIMIT
#define IS_HIGHMEM64_PTR(x) x > HIGH_MEM_64_FLOOR &&x < HIGH_MEM_64_LIMIT

/* Passed to alloc_page() */

#define PAGE_NO_RETRY (1 << 3)

#define PAGE_FLAG_LOCKED (1 << 0)
#define PAGE_FLAG_DIRTY  (1 << 1)
#define PAGE_FLAG_PINNED (1 << 2)

/* PAGE_BUDDY - If set, it means the page is free AND inserted in one of the buddy allocator's
 * orders. Note that not all free pages have PAGE_BUDDY; only the ones that are directly inserted
 * into an order do. If PAGE_BUDDY, priv = order it's inserted into.
 */
#define PAGE_BUDDY            (1 << 3)
#define PAGE_FLAG_BUFFER      (1 << 4) /* Used by the filesystem code */
#define PAGE_FLAG_ANON        (1 << 5)
#define PAGE_FLAG_FILESYSTEM1 (1 << 6) /* Filesystem private flag */
#define PAGE_FLAG_WAITERS     (1 << 7)
#define PAGE_FLAG_UPTODATE    (1 << 8)
#define PAGE_FLAG_WRITEBACK   (1 << 9)
#define PAGE_FLAG_READAHEAD   (1 << 10)
#define PAGE_FLAG_LRU         (1 << 11)
#define PAGE_FLAG_REFERENCED  (1 << 12)
#define PAGE_FLAG_ACTIVE      (1 << 13)

struct vm_object;

/* struct page - Represents every usable page on the system
 * Careful adding fields in - they may increase the memory use exponentially
 */
struct CAPABILITY("page") page
{
    unsigned int ref;
    unsigned int mapcount;
    unsigned long flags;
    struct
    {
        /* page cache data */
        struct vm_object *owner;
        unsigned long pageoff;
    };

    union {
        struct
        {
            struct list_head list_node;
        } page_allocator_node;
        struct
        {
            union {
                struct page *next_allocation;
                struct page *next_virtual_region;
            } next_un;
        };

        struct list_head lru_node;
    };

    unsigned long priv;
#ifdef CONFIG_PAGE_OWNER
    u32 last_owner, last_lock, last_unlock, last_free;
#endif
};

struct memstat;

void page_get_stats(struct memstat *memstat);

struct bootmodule
{
    uintptr_t base;
    size_t size;
    struct bootmodule *next;
};

extern struct page *page_map;
extern unsigned long base_pfn;

static inline unsigned long page_to_pfn(struct page *p)
{
    return (p - page_map) - base_pfn;
}

static inline unsigned long pfn_to_paddr(unsigned long pfn)
{
    return pfn << PAGE_SHIFT;
}

#define page_to_phys(page) (void *) (pfn_to_paddr(page_to_pfn(page)))

#define PAGE_TO_VIRT(page) ((void *) (pfn_to_paddr(page_to_pfn(page)) + PHYS_BASE))

void page_init(size_t memory_size, unsigned long maxpfn);

unsigned int page_hash(uintptr_t p);
struct page *phys_to_page(uintptr_t phys);

/**
 * @brief Retrieve the struct page from a physical address
 * This may fail if phys > maxpfn
 * @param phys Physical address
 * @return Struct page, or NULL if > maxpfn
 */
struct page *phys_to_page_mayfail(uintptr_t phys);
struct page *page_add_page(void *paddr);
struct page *page_add_page_late(void *paddr);

#define PAGE_ALLOC_CONTIGUOUS          (1 << 0)
#define PAGE_ALLOC_NO_ZERO             (1 << 1)
#define PAGE_ALLOC_4GB_LIMIT           (1 << 2)
#define PAGE_ALLOC_INTERNAL_DEBUG      (1 << 3)
#define PAGE_ALLOC_NO_SANITIZER_SHADOW (1 << 4)

#define __GFP_DIRECT_RECLAIM  (1 << 8)
#define __GFP_WAKE_PAGEDAEMON (1 << 9)
#define __GFP_ATOMIC          (1 << 10)
#define __GFP_IO              (1 << 11)
#define __GFP_FS              (1 << 12)
#define __GFP_NO_INSTRUMENT   (1 << 13)
#define __GFP_NOWARN          (1 << 14)
#define __GFP_NOWAIT          (1 << 15)
#define __GFP_MAY_RECLAIM     (__GFP_DIRECT_RECLAIM | __GFP_WAKE_PAGEDAEMON)
#define GFP_KERNEL            (__GFP_MAY_RECLAIM | __GFP_IO)
#define GFP_ATOMIC            (__GFP_ATOMIC | __GFP_WAKE_PAGEDAEMON)
#define GFP_NOIO              (__GFP_MAY_RECLAIM)
#define GFP_NOFS              (__GFP_MAY_RECLAIM | __GFP_IO)
#define GFP_NOWAIT            (__GFP_WAKE_PAGEDAEMON | __GFP_NOWAIT | __GFP_NOWARN)

static inline bool __page_should_zero(unsigned long flags)
{
    return !(flags & PAGE_ALLOC_NO_ZERO);
}

static inline bool gfpflags_allow_blocking(unsigned int gfp_flags)
{
    return !!(gfp_flags & __GFP_DIRECT_RECLAIM);
}

#define page_should_zero(x) likely(__page_should_zero(x))

struct page *alloc_pages(unsigned int order, unsigned long flags);

static inline struct page *alloc_page(unsigned long flags)
{
    return alloc_pages(0, flags);
}

__always_inline unsigned int pages2order(unsigned long pages)
{
    if (pages == 1)
        return 0;
    return ilog2(pages - 1) + 1;
}

/**
 * @brief Allocate a list of pages
 *
 * @param nr_pages Number of pages to allocate
 * @param gfp_flags GFP flags
 * @return List of struct pages linked by next_un.next_allocation, or NULL
 */
struct page *alloc_page_list(size_t nr_pages, unsigned int gfp_flags);

/**
 * @brief Free a list of pages
 *
 * @param pages List of linked struct pages as retrieved from alloc_page_list
 */
void free_page_list(struct page *pages);

void free_page(struct page *p);
void free_pages(struct page *p);

__attribute__((malloc)) void *__ksbrk(long inc);
void __kbrk(void *break_, void *limit);

struct used_pages
{
    uintptr_t start;
    uintptr_t end;
    struct used_pages *next;
};

void page_add_used_pages(struct used_pages *pages);

static inline unsigned long page_ref(struct page *p)
{
    unsigned long newrefs = __atomic_add_fetch(&p->ref, 1, __ATOMIC_ACQUIRE);
    DCHECK(newrefs > 1);
    return newrefs;
}

static inline unsigned long page_ref_many(struct page *p, unsigned long c)
{
    return __atomic_add_fetch(&p->ref, c, __ATOMIC_ACQUIRE);
}

static inline unsigned long __page_unref(struct page *p)
{
    return __atomic_sub_fetch(&p->ref, 1, __ATOMIC_RELEASE);
}

#define page_unref(p) free_page(p)

static inline unsigned long page_unref_many(struct page *p, unsigned long c)
{
    return __atomic_sub_fetch(&p->ref, c, __ATOMIC_RELEASE);
}

static inline void page_pin(struct page *p)
{
    page_ref(p);
}

static inline void page_unpin(struct page *p)
{
    page_unref(p);
}

__always_inline void page_set_waiters(struct page *p)
{
    __atomic_fetch_or(&p->flags, PAGE_FLAG_WAITERS, __ATOMIC_ACQUIRE);
}

__always_inline void page_clear_waiters(struct page *p)
{
    __atomic_fetch_and(&p->flags, ~PAGE_FLAG_WAITERS, __ATOMIC_RELEASE);
}

void page_owner_owned(struct page *p);
void page_owner_freed(struct page *p);
void page_owner_locked(struct page *p);
void page_owner_unlocked(struct page *p);

__always_inline bool try_lock_page(struct page *p) TRY_ACQUIRE(true, p)
{
    unsigned long flags = __atomic_fetch_or(&p->flags, PAGE_FLAG_LOCKED, __ATOMIC_ACQUIRE);
#ifdef CONFIG_PAGE_OWNER
    if (!(flags & PAGE_FLAG_LOCKED))
        page_owner_locked(p);
#endif

    return !(flags & PAGE_FLAG_LOCKED);
}

int page_wait_bit(struct page *p, unsigned int flags, bool interruptible);

__always_inline void lock_page(struct page *p) ACQUIRE(p) NO_THREAD_SAFETY_ANALYSIS
{
    if (unlikely(!try_lock_page(p)))
        page_wait_bit(p, PAGE_FLAG_LOCKED, false);
}

void page_wake_bit(struct page *p, unsigned int bit);

__always_inline void unlock_page(struct page *p) RELEASE(p) NO_THREAD_SAFETY_ANALYSIS
{
#ifdef CONFIG_PAGE_OWNER
    page_owner_unlocked(p);
#endif
    unsigned long flags = __atomic_and_fetch(&p->flags, ~PAGE_FLAG_LOCKED, __ATOMIC_RELEASE);
    if (unlikely(flags & PAGE_FLAG_WAITERS))
        page_wake_bit(p, PAGE_FLAG_LOCKED);
}

__always_inline bool page_test_set_flag(struct page *p, unsigned long flag)
{
    unsigned long word;
    do
    {
        word = __atomic_load_n(&p->flags, __ATOMIC_ACQUIRE);
        if (word & flag)
            return false;
    } while (!__atomic_compare_exchange_n(&p->flags, &word, word | flag, false, __ATOMIC_RELEASE,
                                          __ATOMIC_RELAXED));
    return true;
}

__always_inline bool page_flag_set(struct page *p, unsigned long flag)
{
    return READ_ONCE(p->flags) & flag;
}

__always_inline bool page_locked(struct page *p)
{
    return page_flag_set(p, PAGE_FLAG_LOCKED);
}

__always_inline void page_set_writeback(struct page *p)
{
    __atomic_fetch_or(&p->flags, PAGE_FLAG_WRITEBACK, __ATOMIC_RELEASE);
}

__always_inline void page_clear_writeback(struct page *p)
{
    unsigned long flags = __atomic_and_fetch(&p->flags, ~PAGE_FLAG_WRITEBACK, __ATOMIC_RELEASE);
    if (unlikely(flags & PAGE_FLAG_WAITERS))
        page_wake_bit(p, PAGE_FLAG_WRITEBACK);
}

__always_inline void page_wait_writeback(struct page *p)
{
    while (page_flag_set(p, PAGE_FLAG_WRITEBACK))
        page_wait_bit(p, PAGE_FLAG_WRITEBACK, false);
}

__always_inline void page_set_flag(struct page *p, unsigned long flag)
{
    __atomic_fetch_or(&p->flags, flag, __ATOMIC_RELEASE);
}

void __reclaim_page(struct page *new_page);
void reclaim_pages(unsigned long start, unsigned long end);
void page_allocate_pagemap(unsigned long __maxpfn);

#ifdef __cplusplus
/**
 * @brief Unique_ptr<> like wrapper for pages
 *
 */
class unique_page
{
private:
    /* Hmmm, reference or pointer? I'm preferring pointer here because it's more flexible;
     * you can use operator= to re-assign stuff.
     */
    page *res;

public:
    constexpr unique_page() : res{nullptr}
    {
    }
    constexpr unique_page(page *r) : res{r}
    {
    }

    unique_page(const unique_page &ar) = delete;

    unique_page &operator=(const unique_page &ar) = delete;

    bool valid_resource() const
    {
        return res != nullptr;
    }

    unique_page(unique_page &&ar) : res{ar.res}
    {
        ar.res = nullptr;
    }

    unique_page &operator=(unique_page &&ar)
    {
        res = ar.res;
        ar.res = nullptr;

        return *this;
    }

    ~unique_page()
    {
        if (valid_resource())
            free_pages(res);
    }

    page *release()
    {
        auto ret = res;
        res = nullptr;

        return ret;
    }

    page *get() const
    {
        return res;
    }

    operator bool() const
    {
        return valid_resource();
    }

    bool operator!() const
    {
        return !valid_resource();
    }

    page *operator->() const
    {
        return get();
    }

    operator page *() const
    {
        return get();
    }

    bool operator==(const unique_page &rhs) const
    {
        return get() == rhs.get();
    }
};

/**
 * @brief Allocate a unique_page
 *
 * @param flags Flags passed to alloc_page
 * @return A unique_page (may or may not be null)
 */
static inline unique_page make_unique_page(unsigned long flags)
{
    return alloc_page(flags);
}

/**
 * @brief Allocate a unique_page
 *
 * @param nr_pages Number of pages
 * @param flags Flags passed to alloc_pages
 * @return A unique_page (may or may not be null)
 */
static inline unique_page make_unique_pages(unsigned long nr_pages, unsigned long flags)
{
    return alloc_pages(nr_pages, flags);
}

#endif

extern uint64_t kernel_phys_offset;
/**
 * @brief Get the kernel's physical load offset
 *
 * @return Load offset
 */
static inline uint64_t get_kernel_phys_offset()
{
    return kernel_phys_offset;
}

/**
 * @brief Calculate the number of pages under the high watermark in every zone, for every node
 *
 * @return Number of pages under the high watermark
 */
unsigned long pages_under_high_watermark();

/**
 * @brief Drain pages from all zones' pcpu caches
 *
 */
void page_drain_pcpu();

enum page_stat
{
    NR_FILE = 0,
    NR_SHARED,
    NR_ANON,
    NR_DIRTY,
    NR_WRITEBACK,
    NR_SLAB_RECLAIMABLE,
    NR_SLAB_UNRECLAIMABLE,
    /* LRU currently not implemented */
    NR_INACTIVE_FILE,
    NR_ACTIVE_FILE,
    NR_INACTIVE_ANON,
    NR_ACTIVE_ANON,
    PAGE_STATS_MAX,
};

void inc_page_stat(struct page *page, enum page_stat stat);
void dec_page_stat(struct page *page, enum page_stat stat);

void page_accumulate_stats(unsigned long pages[PAGE_STATS_MAX]);

struct page_lru;
struct page_lru *page_to_page_lru(struct page *page);

void page_promote_referenced(struct page *page);

static inline void page_reset_mapcount(struct page *page)
{
    /* mapcount is -1 biased */
    WRITE_ONCE(page->mapcount, -1);
}

static inline unsigned int page_mapcount(struct page *page)
{
    return READ_ONCE(page->mapcount) + 1;
}

static inline void page_add_mapcount(struct page *page)
{
    if (__atomic_add_fetch(&page->mapcount, 1, __ATOMIC_RELAXED) == 0)
        page_ref(page);
}

static inline void page_sub_mapcount(struct page *page)
{
    if (__atomic_sub_fetch(&page->mapcount, 1, __ATOMIC_RELAXED) == -1U)
        page_unref(page);
}

void bug_on_page(struct page *page, const char *expr, const char *file, unsigned int line,
                 const char *func);

#define DCHECK_PAGE(expr, page) \
    if (unlikely(!(expr)))      \
        bug_on_page(page, #expr, __FILE__, __LINE__, __func__);

#define CHECK_PAGE(expr, page) \
    if (unlikely(!(expr)))     \
        bug_on_page(page, #expr, __FILE__, __LINE__, __func__);

static inline void page_set_anon(struct page *page)
{
    __atomic_or_fetch(&page->flags, PAGE_FLAG_ANON, __ATOMIC_RELEASE);
    inc_page_stat(page, NR_ANON);
}

__END_CDECLS

#endif
