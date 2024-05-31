/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_MM_PAGE_NODE_H
#define _ONYX_MM_PAGE_NODE_H

#include <onyx/list.h>
#include <onyx/mm/page_zone.h>
#include <onyx/spinlock.h>

struct page_node
{
    struct spinlock node_lock;
    struct list_head cpu_list_node;
    unsigned long used_pages;
    unsigned long total_pages;
    struct page_zone zones[NR_ZONES];

#ifdef __cplusplus
    struct page_zone *pick_zone(unsigned long page);

    constexpr page_node() : node_lock{}, cpu_list_node{}, used_pages{}, total_pages{}
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
#endif
};

/* ugh */

__BEGIN_CDECLS
extern struct page_node main_node;

#define for_zones_in_node(node, zone) \
    for (zone = node->zones; zone < node->zones + NR_ZONES; zone++)

__END_CDECLS
#endif
