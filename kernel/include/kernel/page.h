/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PAGE_H
#define _KERNEL_PAGE_H

#include <stddef.h>

#include <kernel/spinlock.h>
#include <kernel/compiler.h>
#if defined(__x86_64__)

#define PAGES_PER_AREA 512
#define MAX_ORDER 17
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


/* Passed to __alloc_page() */
#define PAGE_AREA_DMA (1 << 0)
#define PAGE_AREA_HIGH_MEM 	(1 << 1)
#define PAGE_AREA_HIGH_MEM_64 	(1 << 2)
#define PAGE_NO_RETRY		(1 << 3)

struct page
{
	void *vaddr;
	void *phaddr;
	int area;
};
typedef struct page_area
{
	struct page_area *prev;
	struct page_area *next;
} page_area_t;

typedef struct page_zone
{
	/* We obviously need a lock to protect this page zone */
	spinlock_t lock __attribute__((aligned(16)));
	/* Let's keep linked lists pointing to blocks of 2^1 to 2^MAX_ORDER-1(NOT WORKING AS I DO NOT HAVE A BUDDY ALLOCATOR) */
	page_area_t *free_areas __attribute__((aligned(16)));
	/* The name of the page zone */
	char *name;
	/* The size of the page zone */
	size_t size;
	/* The allocated/free pages */
	size_t allocated_pages, free_pages;

} page_zone_t;

void *__alloc_page(int opt);
void *__alloc_page_huge(int opt);
void __free_page(void *page);
void __free_pages(void *pages, size_t nr);

void page_init(void);
#endif