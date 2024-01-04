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
        dec_page_stat(page, NR_ANON);
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
 * @param nocopy Don't copy if we find an old page
 * @return 0 on success, negative error codes
 */
int amap_add(struct amap *amap, struct page *page, struct vm_area_struct *region, size_t pgoff,
             bool nocopy)
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

    if (!nocopy && old != 0)
    {
        struct page *oldp = (struct page *) old;
        copy_page_to_page(page_to_phys(page), page_to_phys(oldp));
    }

    inc_page_stat(page, NR_ANON);
    return 0;
}

/**
 * @brief Get a page from the amap
 *
 * @param amap Amap to lookup from
 * @param pgoff Page offset (in pfn, shifted right by PAGE_SHIFT)
 * @return struct page in the amap, or NULL
 */
struct page *amap_get(struct amap *amap, size_t pgoff)
{
    scoped_lock g{amap->am_lock};
    auto ex = amap->am_map.get(pgoff);
    if (ex.has_error())
        return nullptr;
    struct page *page = (struct page *) ex.value();
    page_ref(page);
    return page;
}

/**
 * @brief Split an amap into two
 *
 * @param amap Original amap
 * @param region Region to which the amap belongs
 * @param pgoff Page offset for the new amap
 * @return New amap, or NULL
 */
struct amap *amap_split(struct amap *amap, struct vm_area_struct *region, size_t pgoff)
{
    if (amap->am_refc > 1) [[unlikely]]
    {
        /* Note: We do not need a lock here, no one can touch this amap while am_refc > 1 */
        struct amap *namap = amap_copy(amap);
        if (!namap)
            return nullptr;

        amap_unref(amap);
        amap = namap;
        region->vm_amap = amap;
    }

    struct amap *namap = amap_alloc(0);
    if (!namap)
        return nullptr;

    /* Since we are the exclusive owners of this amap, and callers hold the mm address space lock,
     * we do not need to lock. This saves us from GFP_ATOMIC.
     */
    auto cursor = radix_tree::cursor::from_range(&amap->am_map, pgoff);
    while (!cursor.is_end())
    {
        /* Move pages from one amap to the other by storing to new and store(0). store(0) is done
         * later in case of OOM.
         */
        unsigned long curr_idx = cursor.current_idx() - pgoff;
        if (namap->am_map.store(curr_idx, cursor.get()) < 0)
            goto err;
        cursor.advance();
    }

    cursor = radix_tree::cursor::from_range(&amap->am_map, pgoff);
    while (!cursor.is_end())
    {
        /* store(0) is done now..
         */
        cursor.store(0);
        cursor.advance();
    }

    return namap;
err:
    /* Open-coded amap_free, to avoid page_ref/page_unref shenanigans. */
    amap->~amap();
    kfree(amap);
    return nullptr;
}

/**
 * @brief Truncate an amap
 *
 * @param amap Amap
 * @param region Region to which the amap belongs
 * @param new_pgsize New size, in pages
 * @return 0 on success, negative error codes
 */
int amap_truncate(struct amap *amap, struct vm_area_struct *region, size_t new_pgsize)
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

    auto cursor = radix_tree::cursor::from_range(&amap->am_map, new_pgsize);

    while (!cursor.is_end())
    {
        struct page *page = (struct page *) cursor.get();
        dec_page_stat(page, NR_ANON);
        page_unref(page);
        cursor.store(0);
        cursor.advance();
    }

    return 0;
}

/**
 * @brief Punch a hole through an amap
 *
 * @param amap Amap
 * @param region Region to which the amap belongs
 * @param first_pg First pfn of the hole
 * @param end_pg End of the hole
 * @return 0 on success, negative error codes
 */
int amap_punch_hole(struct amap *amap, struct vm_area_struct *region, size_t first_pg,
                    size_t end_pg)
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

    auto cursor = radix_tree::cursor::from_range(&amap->am_map, first_pg, end_pg);

    while (!cursor.is_end())
    {
        struct page *page = (struct page *) cursor.get();
        dec_page_stat(page, NR_ANON);
        page_unref(page);
        cursor.store(0);
        cursor.advance();
    }

    return 0;
}
