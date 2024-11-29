/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/process.h>
#include <onyx/vm.h>

#undef REQUIRES_SHARED
#define REQUIRES_SHARED(...)

// TODO: Export this stuff in some header, and avoid sticking everything into vm.cpp
vm_area_struct *vm_search(struct mm_address_space *mm, void *addr, size_t length)
    REQUIRES_SHARED(mm->vm_lock);

static long do_pagemap(struct mm_address_space *as, unsigned long start, unsigned long end,
                       u64 *pagemap)
{

    scoped_rwlock<rw_lock::read> g{as->vm_lock};
    long pfns_processed = 0;

    vm_area_struct *vma;
    unsigned long index = start;
    void *entry_;
    mt_for_each (&as->region_tree, entry_, index, end)
    {
        vma = (vm_area_struct *) entry_;
        if (vma->vm_start > end)
            break;

        spin_lock(&as->page_table_lock);

        /* Note: This is bad and slow(er). Nonetheless, it does the job for now */
        for (; start < end; start += PAGE_SIZE)
            pagemap[pfns_processed++] = __get_mapping_info((void *) start, as);

        spin_unlock(&as->page_table_lock);

        if (start == end)
            break;
    }

    return pfns_processed;
}

int sys_mpagemap(void *addr, size_t length, u64 *pagemap)
{
    unsigned long start = (unsigned long) addr & -PAGE_SIZE;
    length += (unsigned long) addr & (PAGE_SIZE - 1);
    unsigned long end = ALIGN_TO(start + length, PAGE_SIZE);
    struct mm_address_space *as = get_current_address_space();
    struct page *buffer;
    int ret = 0;

    if (start < as->start || end > as->end + 1)
        return -EINVAL;

    buffer = alloc_page(GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    while (start < end)
    {
        /* Limit runs to PAGE_SIZE / sizeof(u64) */
        u64 *kbuffer = (u64 *) PAGE_TO_VIRT(buffer);
        unsigned long this_run_end = cul::min(end, start + (PAGE_SIZE / sizeof(u64)));
        long processed = do_pagemap(as, start, this_run_end, kbuffer);

        if (processed == 0)
            break;

        if (processed < 0)
        {
            ret = processed;
            break;
        }

        if (copy_to_user(pagemap, kbuffer, processed * sizeof(u64)) < 0)
        {
            ret = -EFAULT;
            break;
        }

        pagemap += processed;
        start += processed << PAGE_SHIFT;
    }

    free_page(buffer);

    return ret;
}
