/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_MM_AMAP_H
#define _ONYX_MM_AMAP_H

#include <onyx/page.h>
#include <onyx/radix.h>
#include <onyx/spinlock.h>

struct amap
{
    radix_tree am_map;
    unsigned long am_refc;
    size_t am_size; /* size looks redundant? */
    struct spinlock am_lock;

    template <typename Callable>
    void for_range(Callable c, unsigned long start, unsigned long end = -1ul)
    {
        radix_tree::cursor cursor = radix_tree::cursor::from_range(&am_map, start, end);

        while (!cursor.is_end())
        {
            struct page *page = (struct page *) cursor.get();
            if (!c(page, cursor.current_idx()))
                break;
            cursor.advance();
        }
    }
};

/**
 * @brief Allocate a new anonymous memory map
 *
 * @param size Size of the amap
 * @return struct amap*
 */
struct amap *amap_alloc(size_t size);

/**
 * @brief Free an amap
 *
 * @param amap amap to free
 */
void amap_free(struct amap *amap);

__always_inline void amap_ref(struct amap *amap)
{
    __atomic_add_fetch(&amap->am_refc, 1, __ATOMIC_ACQUIRE);
}

__always_inline void amap_unref(struct amap *amap)
{
    if (__atomic_sub_fetch(&amap->am_refc, 1, __ATOMIC_RELEASE) == 0)
        amap_free(amap);
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
             bool nocopy);
/**
 * @brief Add a page to an amap
 *
 * @param amap Amap to add to
 * @param page Page to add
 * @param region Region to which the amap belongs
 * @param pgoff Page offset (in pfn, shifted right by PAGE_SHIFT)
 * @return 0 on success, negative error codes
 */
__always_inline int amap_ref_and_add(struct amap *amap, struct page *page,
                                     struct vm_area_struct *region, size_t pgoff)
{
    page_ref(page);
    return amap_add(amap, page, region, pgoff, false);
}

/**
 * @brief Get a page from the amap
 *
 * @param amap Amap to lookup from
 * @param pgoff Page offset (in pfn, shifted right by PAGE_SHIFT)
 * @return struct page in the amap, or NULL
 */
struct page *amap_get(struct amap *amap, size_t pgoff);

/**
 * @brief Split an amap into two
 *
 * @param amap Original amap
 * @param region Region to which the amap belongs
 * @param pgoff Page offset for the new amap
 * @return New amap, or NULL
 */
struct amap *amap_split(struct amap *amap, struct vm_area_struct *region, size_t pgoff);

/**
 * @brief Truncate an amap
 *
 * @param amap Amap
 * @param region Region to which the amap belongs
 * @param new_pgsize New size, in pages
 * @return 0 on success, negative error codes
 */
int amap_truncate(struct amap *amap, struct vm_area_struct *region, size_t new_pgsize);

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
                    size_t end_pg);

#endif
