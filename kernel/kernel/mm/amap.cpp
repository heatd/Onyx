/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/mm/amap.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>

__always_inline void amap_init(struct amap *amap)
{
    new (amap) struct amap;
    spinlock_init(&amap->am_lock);
    amap->am_refc = 1;
    amap->am_size = 0;
}

/**
 * @brief Allocate a new anonymous memory map
 *
 * @param size Size of the amap
 * @return struct amap*
 */
struct amap *amap_alloc(size_t size)
{
    struct amap *amap = (struct amap *) kmalloc(sizeof(struct amap), GFP_KERNEL);
    if (!amap)
        return nullptr;
    amap_init(amap);
    amap->am_size = size;

    return amap;
}

void amap_free(struct amap *amap)
{
    DCHECK(amap->am_refc == 0);
    auto cursor = radix_tree::cursor::from_index(&amap->am_map);

    while (!cursor.is_end())
    {
        auto page = (struct page *) cursor.get();
        free_page(page);
        cursor.advance();
    }

    amap->~amap();
    kfree(amap);
}

/**
 * @brief Create a copy of an amap
 *
 * @param amap amap to copy
 * @return New amap, or NULL in case of OOM
 */
static struct amap *amap_copy(struct amap *amap)
{
    struct amap *namap = amap_alloc(amap->am_size);
    if (!namap)
        return nullptr;
    auto ex = amap->am_map.copy(
        [](unsigned long entry, void *ctx) -> unsigned long {
            struct page *page = (struct page *) entry;
            page_ref(page);
            return entry;
        },
        nullptr);
    if (ex.has_error())
    {
        amap_free(namap);
        return nullptr;
    }

    namap->am_map = cul::move(ex.value());
    return namap;
}

/**
 * @brief Add a page to an amap
 *
 * @param amap Amap to add to
 * @param page Page to add
 * @param region Region to which the amap belongs
 * @param pgoff Page offset (in pfn, shifted right by PAGE_SHIFT)
 * @return 0 on success, negative error codes
 */
int amap_add(struct amap *amap, struct page *page, struct vm_region *region, size_t pgoff)
{
    if (amap->am_refc > 1) [[unlikely]]
    {
        /* Note: We do not need a lock here, no one can touch this amap while am_refc > 1 */
        struct amap *namap = amap_copy(amap);
        if (!namap)
            return -ENOMEM;

        amap_unref(amap);
        amap = namap;
        region->vm_amap = amap;
    }

    scoped_lock g{amap->am_lock};
    auto old = amap->am_map.xchg(pgoff, (unsigned long) page);
    if (radix_err(old))
        return old;

    if (old != 0)
    {
        struct page *oldp = (struct page *) old;
        copy_page_to_page(page_to_phys(page), page_to_phys(oldp));
    }

    return 0;
}
