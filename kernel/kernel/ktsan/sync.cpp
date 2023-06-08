/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/assert.h>
#include <onyx/fnv.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>

#include "ktsan.h"

#include <onyx/pair.hpp>

void kt_sync_acquire(kt_sync_obj *sobj, kt_thread *thr)
{
    kt_clk_acquire(&thr->clk, &sobj->clk);
}

void kt_sync_release(kt_sync_obj *sobj, kt_thread *thr)
{
    kt_clk_acquire(&sobj->clk, &thr->clk);
}

static slab_cache *sync_obj_cache = nullptr;

kt_sync_obj *kt_sync_alloc()
{
    return (kt_sync_obj *) kmem_cache_alloc(
        sync_obj_cache, GFP_KERNEL | PAGE_ALLOC_NO_SANITIZER_SHADOW | GFP_HACK_VMALLOC_TRY_LOCK);
}

void kt_sync_free(kt_sync_obj *obj)
{
    kmem_cache_free(sync_obj_cache, obj);
}

#define KT_SYNC_HASHMAP_SIZE 4096
#define KT_SYNC_HASHMAP_MASK (KT_SYNC_HASHMAP_SIZE - 1)
static struct spinlock table_lock;
static struct list_head hashmap[KT_SYNC_HASHMAP_SIZE];

// TODO: We need to have a way to easily free sync objects.
// It's probably not a big deal at the moment, but it needs to be fixed

/**
 * @brief Find or create a sync object
 *
 * @param addr Address of the sync object
 * @param thr Current kt_thread
 * @return A pointer to the kt_sync_obj, and a bool 'created'
 */
cul::pair<kt_sync_obj *, bool> kt_sync_find_or_create(unsigned long addr, kt_thread *thr)
{
    scoped_lock g{table_lock};
    auto hash = fnv_hash(&addr, sizeof(unsigned long)) & KT_SYNC_HASHMAP_MASK;

    struct list_head *ch = &hashmap[hash];
    list_for_every (ch)
    {
        kt_sync_obj *obj = container_of(l, kt_sync_obj, node);

        if (obj->addr == addr)
            return {obj, false};
    }

    kt_sync_obj *obj = kt_sync_alloc();
    if (!obj)
        return {nullptr, false};
    list_add_tail(&obj->node, ch);
    kt_sync_init(obj, thr);
    obj->addr = addr;

    return {obj, true};
}

void kt_init_sync_cache()
{
    sync_obj_cache =
        kmem_cache_create("kt_sync_obj", sizeof(kt_sync_obj), 0, KMEM_CACHE_NOPCPU, nullptr);
    CHECK(sync_obj_cache != nullptr);

    // Now that we're in here, init the hashmap too
    for (auto &hc : hashmap)
        INIT_LIST_HEAD(&hc);
}
