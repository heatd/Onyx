/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/ktsan.h>
#include <onyx/page.h>
#include <onyx/paging.h>
#include <onyx/vm.h>

#include "ktsan.h"

#include <onyx/atomic.hpp>

atomic<unsigned long> alloc_shadow_failure = 0;

int kt_alloc_pages(struct page *page, size_t nr)
{
    // If IRQs are disabled, we can't use vmalloc, so bail
    // This memory will not be covered by ktsan. Too bad. This should not be common.
    // TODO: Add a buddy page allocator that can allocate shadow with irqs off, without vmalloc.
    if (irq_is_disabled())
        return 0;

    for (; nr != 0; page = page->next_un.next_allocation, nr--)
    {
        // For every page, allocate a shadow region in vmalloc
        if (page->shadow)
            continue; // Someone already allocated a shadow for this, continue
        page->shadow = vmalloc(1UL << KTSAN_SHADOW_SLOTS_LOG, VM_TYPE_REGULAR, VM_READ | VM_WRITE,
                               GFP_KERNEL | PAGE_ALLOC_NO_SANITIZER_SHADOW);
        if (!page->shadow)
        {
            // Ohno! increment a counter and keep going
            alloc_shadow_failure++;
        }
    }

    return 0;
}

void kt_free_pages(struct page *page, size_t nr)
{
    // TODO
}

kt_shadow *kt_get_shadow(void *addr)
{
    auto mapping = get_mapping_info(addr);
    CHECK(mapping & PAGE_PRESENT);
    unsigned long paddr = MAPPING_INFO_PADDR(mapping);
    struct page *page = phys_to_page_mayfail(paddr);

    if (!page || !page->shadow)
        return nullptr;

    const auto page_off = ((unsigned long) addr & (PAGE_SIZE - 1));
    return ((kt_shadow *) page->shadow) + (page_off >> 3) * KTSAN_SHADOW_SLOTS;
}

void kt_clear_shadow_one(unsigned long addr)
{
    kt_shadow *s = kt_get_shadow((void *) addr);
    for (unsigned long i = 0; i < KTSAN_SHADOW_SLOTS; i++)
        __atomic_store_n(&s[i].word, 0, __ATOMIC_RELEASE);
}
