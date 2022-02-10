/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include <onyx/bootmem.h>
#include <onyx/fnv.h>
#include <onyx/log.h>
#include <onyx/page.h>
#include <onyx/vm.h>

/* struct page array a-la linux kernel */
struct page *page_map = NULL;
static size_t num_pages = 0;
static unsigned long maxpfn = 0;
unsigned long base_pfn = 0;

struct page *page_add_page(void *paddr)
{
    struct page *page = phys_to_page((unsigned long) paddr);

    assert(page != NULL);
    memset(page, 0, sizeof(struct page));

    ++num_pages;

    return page;
}

void page_allocate_pagemap(unsigned long __maxpfn)
{
    maxpfn = __maxpfn;
    page_map = (page *) __ksbrk((maxpfn - base_pfn) * sizeof(struct page));
}

struct page *phys_to_page(uintptr_t phys)
{
    unsigned long pfn = phys >> PAGE_SHIFT;
    assert(pfn <= maxpfn);
    return page_map + pfn - base_pfn;
}

extern unsigned char kernel_start;
extern unsigned char kernel_end;

/**
 * @brief Retrieves the kernel's limits in physical memory and virtual memory.
 *
 * @param l A pointer to a kernel_limits object where the limits will be placed.
 */
void get_kernel_limits(struct kernel_limits *l)
{
    uintptr_t start_virt = (uintptr_t) &kernel_start;
    uintptr_t end_virt = (uintptr_t) &kernel_end;

    l->start_virt = start_virt;
    l->end_virt = end_virt;

    l->start_phys = start_virt - KERNEL_VIRTUAL_BASE;
    l->end_phys = end_virt - KERNEL_VIRTUAL_BASE;
}

bool klimits_present = false;

bool check_kernel_limits(void *__page)
{
    static struct kernel_limits l;
    uintptr_t page = (uintptr_t) __page;

    if (!klimits_present)
    {
        klimits_present = true;
        get_kernel_limits(&l);
        printf("Kernel limits: %lx-%lx phys, %lx-%lx virt\n", l.start_phys, l.end_phys,
               l.start_virt, l.end_virt);
    }

    if (page >= l.start_phys && page < l.end_phys)
        return true;

    return false;
}

void reclaim_pages(unsigned long start, unsigned long end)
{
    unsigned long page_start = (unsigned long) page_align_up((void *) start);

    end &= ~(PAGE_SIZE - 1);
    size_t nr_pages = (end - page_start) / PAGE_SIZE;
    for (size_t i = 0; i < nr_pages; i++)
    {
        struct page *p = page_add_page((void *) page_start);

        __reclaim_page(p);
        page_start += PAGE_SIZE;
    }
}
