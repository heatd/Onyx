/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PAGE_H
#define _KERNEL_PAGE_H

#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

#include <onyx/spinlock.h>
#include <onyx/compiler.h>
#include <onyx/list.h>
#include <onyx/ref.h>

/* The default physical allocator is the buddy allocator */
#define CONFIG_BUDDY_ALLOCATOR		1
#if defined(__x86_64__)

#include <onyx/x86/page.h>

#define PAGES_PER_AREA 512
#define MAX_ORDER 11
#define HUGE_PAGE_SIZE 0x200000

#define DMA_UPPER_LIMIT (void*) 0x1000000
#define HIGH_MEM_FLOOR  DMA_UPPER_LIMIT
#define HIGH_MEM_LIMIT  (void*) 0xFFFFFFFF
#define HIGH_MEM_64_FLOOR HIGH_MEM_LIMIT
#define HIGH_MEM_64_LIMIT (void*) -1

#else
#error "Define PAGES_PER_AREA and/or MAX_ORDER"
#endif

#define NR_ZONES 3
#define IS_HUGE_ALIGNED(x) (((unsigned long) x % HUGE_PAGE_SIZE) ? 0 : 1)
#define ALIGN_TO(x, y) (((unsigned long)x + (y - 1)) & -y)
#define IS_DMA_PTR(x) x < DMA_UPPER_LIMIT
#define IS_HIGHMEM_PTR(x) x > HIGH_MEM_FLOOR && x < HIGH_MEM_LIMIT
#define IS_HIGHMEM64_PTR(x) x > HIGH_MEM_64_FLOOR && x < HIGH_MEM_64_LIMIT

#define ilog2(X) ((unsigned) (8*sizeof (unsigned long long) - __builtin_clzll((X)) - 1))


/* Passed to alloc_page() */

#define PAGE_NO_RETRY		(1 << 3)

/* struct page - Represents every usable page on the system 
 * Everything is native-word-aligned in order to allow atomic changes
 * Careful adding fields in - they may increase the memory use exponentially
*/
struct page
{
	void *paddr;
	struct page *next;
	unsigned long ref;

	union
	{
		unsigned long flags;
		struct page_cache_block *cache;
	};

	size_t off;		/* Offset in vmo */

	union
	{
		struct page *next_allocation;
		struct page *next_virtual_region;
	} next_un;
};

#define PAGE_TO_VIRT(page)	((struct page *)((unsigned long) page->paddr + PHYS_BASE))
#define PAGE_HASHTABLE_ENTRIES 0x4000	
struct page_hashtable
{
	struct page *table[PAGE_HASHTABLE_ENTRIES];
};

#ifdef CONFIG_BUDDY_ALLOCATOR
/* A structure describing areas of size 2^order pages */
typedef struct free_area
{
	/* Each of them contains a list of free pages */
	struct list_head free_list;
	/* And a bitmap of buddies */
	unsigned long *map;
	/* Each "sub-zone" has a buddy, and to merge an area into a larger area, 
	 * we need both buddies to be free; because of that, we use a bitmap of buddies to represent them.
	 * We use a bit for each buddy, if it's set, the buddy is allocated, if not, it's set to 0.
	*/
} free_area_t;

#else

typedef struct page_zone
{
	/* We obviously need a lock to protect this page zone */
	struct spinlock lock __attribute__((aligned(16)));
	0t *free_areas __attribute__((aligned(16)));
	/* The name of the page zone */
	char *name;
	/* The size of the page zone */
	size_t size;
	/* The allocated/free pages */
	size_t allocated_pages, free_pages;

} page_zone_t;

typedef struct 0
{
	struct 0 *prev;
	struct 0 *next;
} 0t;

#endif /* CONFIG_BUDDY_ALLOCATOR */

struct memstat
{
	size_t free_mem;
	size_t allocated_mem;
};

#ifdef __cplusplus
extern "C" {
#endif

void page_get_stats(struct memstat *memstat);


struct bootmodule
{
	uintptr_t base;
	size_t size;
	struct bootmodule *next;
};

void page_init(size_t memory_size, void *(*get_phys_mem_region)
	(uintptr_t *base, uintptr_t *size, void *context),
	struct bootmodule *modules);

unsigned int page_hash(uintptr_t p);
struct page *phys_to_page(uintptr_t phys);
struct page *page_add_page(void *paddr);
void page_add_page_late(void *paddr);

#define PAGE_ALLOC_CONTIGUOUS	(1 << 0)
#define PAGE_ALLOC_NO_ZERO	(1 << 1)

static inline bool __page_should_zero(unsigned long flags)
{
	return !(flags & PAGE_ALLOC_NO_ZERO);
}

#define page_should_zero(x)		likely(__page_should_zero(x))

struct page *alloc_pages(size_t nr_pages, unsigned long flags);

static inline struct page *alloc_page(unsigned long flags)
{
	return alloc_pages(1, flags);
}

void free_page(struct page *p);
void free_pages(struct page *p);

__attribute__((malloc))
void *__ksbrk(long inc);
void __kbrk(void *break_);

struct used_pages
{
	uintptr_t start;
	uintptr_t end;
	struct used_pages *next;
};

void page_add_used_pages(struct used_pages *pages);

static inline unsigned long page_ref(struct page *p)
{
	return __atomic_add_fetch(&p->ref, 1, __ATOMIC_ACQUIRE);
}

static inline unsigned long page_unref(struct page *p)
{
	return __atomic_sub_fetch(&p->ref, 1, __ATOMIC_RELEASE);
}

#ifdef __cplusplus
}
#endif
#endif
