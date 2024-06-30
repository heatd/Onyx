/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_MM_PAGE_ZONE_H
#define _ONYX_MM_PAGE_ZONE_H

#include <onyx/list.h>
#include <onyx/mm/page_lru.h>
#include <onyx/page.h>

#ifndef CONFIG_SMP_NR_CPUS
#define CONFIG_SMP_NR_CPUS 64
#endif

#define PAGEALLOC_NR_ORDERS 14

struct page_pcpu_data
{
    struct list_head page_list;
    unsigned long nr_pages;
    unsigned long nr_fast_path;
    unsigned long nr_slow_path;
    unsigned long nr_queue_reclaims;
    long pagestats[PAGE_STATS_MAX];

#ifdef __cplusplus
    constexpr page_pcpu_data() : nr_pages{}, nr_fast_path{}, nr_slow_path{}, nr_queue_reclaims{}
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
#endif

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
    struct page_lru zone_lru;
    struct spinlock lock;
    struct page_pcpu_data pcpu[CONFIG_SMP_NR_CPUS] __align_cache;
};

#ifdef __cplusplus
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
    page_lru_init(&zone->zone_lru);
}
#endif

#endif
