/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <stdbool.h>
#include <stdio.h>

#include <onyx/dma.h>
#include <onyx/page.h>
#include <onyx/utils.h>
#include <onyx/vm.h>

static void *expand_array(void *old, size_t new_size)
{
    return realloc(old, new_size);
}

static bool try_to_merge(uintptr_t buf, size_t size, size_t max_size, struct phys_ranges *ranges)
{
    /* Try to merge the new range with an old range by checking the last
     * range. If r->addr + r->size == buf, this means the two areas are
     * contiguous. But, since this is DMA code, we need to check if an
     * area is too big and the hardware doesn't support such a size, so
     * in reality the condition is (r->addr + r->size == buf) &&
     * r->size + size <= max_size.
     */
    if (!ranges->nr_ranges)
        return false;

    size_t last = ranges->nr_ranges - 1;

    struct phys_range *r = ranges->ranges[last];

    /* Perfect! Merge the two entries and return success */
    if (r->addr + r->size == buf && r->size + size <= max_size)
    {
        r->size += size;
        return true;
    }

    return false;
}

int __dma_add_range(uintptr_t virtual_buf, size_t size, size_t max_size, struct phys_ranges *ranges)
{
    struct page *p;

    unsigned long vpage_off = virtual_buf & (PAGE_SIZE - 1);

    if (get_phys_pages((void *) (virtual_buf - vpage_off), GPP_WRITE, &p, 1) < 0)
        return -1;

    unsigned long phys_buf = (unsigned long) page_to_phys(p) + vpage_off;

    if (try_to_merge(phys_buf, size, max_size, ranges) == true)
        return 0;

    size_t idx = ranges->nr_ranges;

    void *n = expand_array(ranges->ranges, (ranges->nr_ranges + 1) * sizeof(struct phys_range *));

    if (!n)
        return -1;

    ranges->ranges = (struct phys_range **) n;

    ranges->ranges[idx] = (phys_range *) malloc(sizeof(struct phys_range));

    if (!ranges->ranges[idx])
        return -1;

    ranges->ranges[idx]->addr = phys_buf;
    ranges->ranges[idx]->size = size;
    ranges->nr_ranges++;

    return 0;
}

int dma_get_ranges(const void *vbuf, size_t buf_size, size_t max_range, struct phys_ranges *ranges)
{
    uintptr_t buf = (uintptr_t) vbuf;
    ranges->nr_ranges = 0;
    ranges->ranges = NULL;

    while (buf_size != 0)
    {
        /* Handle non-page-aligned buffers by doing it a page at a time */
        size_t buf_page_size = PAGE_SIZE - (buf & (PAGE_SIZE - 1));
        size_t s = min(buf_page_size, buf_size);
        s = min(s, max_range);

        if (__dma_add_range(buf, s, max_range, ranges) < 0)
        {
            dma_destroy_ranges(ranges);
            return -1;
        }

        buf_size -= s;
        buf += s;
    }

    return 0;
}

void dma_destroy_ranges(struct phys_ranges *ranges)
{

    for (size_t i = 0; i < ranges->nr_ranges; i++)
    {
        struct phys_range *phys_range = ranges->ranges[i];

        unsigned long base_page = phys_range->addr & -PAGE_SIZE;
        unsigned long base_off = phys_range->addr & (PAGE_SIZE - 1);

        unsigned long total_pages = (phys_range->size + base_off) >> PAGE_SHIFT;

        while (total_pages--)
        {
            struct page *p = phys_to_page(base_page);
            page_unpin(p);
            base_page += PAGE_SIZE;
        }
    }

    for (size_t i = 0; i < ranges->nr_ranges; i++)
        free(ranges->ranges[i]);
    free(ranges->ranges);
}
