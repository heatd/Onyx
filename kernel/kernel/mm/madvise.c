/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdbool.h>

#include <onyx/page.h>
#include <onyx/pgtable.h>
#include <onyx/types.h>
#include <onyx/vm.h>

#include <uapi/mman.h>

static bool madvise_needs_write(int advice)
{
    return true;
}

static bool madvise_valid_advice(int advice)
{
    switch (advice)
    {
        case MADV_DONTNEED:
            return true;
    }

    return false;
}

static int do_madvise_vma(struct vm_area_struct *vma, unsigned long start, unsigned long end,
                          int advice)
{
    switch (advice)
    {
        case MADV_DONTNEED:
            return zap_page_range(start, end, vma);
    }

    WARN_ON(1);
    return -ENOSYS;
}

static int do_madvise_walk(struct mm_address_space *mm, unsigned long start, size_t len, int advice)
{
    unsigned long limit = start + len;
    unsigned long last_vma_end = start;
    int ret = -ENOMEM;
    struct vm_area_struct *vma;

    MA_STATE(mas, &mm->region_tree, start, limit - 1);

    mas_for_each(&mas, vma, limit - 1)
    {
        /* Break if we see a gap between VMAs, or if this vma is beyond limit */
        if (vma->vm_start >= limit)
            break;

        if (vma->vm_start != last_vma_end)
        {
            ret = -ENOMEM;
            break;
        }

        ret = do_madvise_vma(vma, max(vma->vm_start, start), min(limit, vma->vm_end), advice);
        if (ret)
            break;
        last_vma_end = vma->vm_end;
    }

    return ret;
}

int sys_madvise(void *addr, size_t len, int advice)
{
    int ret;
    unsigned long start = (unsigned long) addr;
    /* TODO: Remove this open coding */
    struct mm_address_space *mm = get_current_thread()->aspace;

    if (!madvise_valid_advice(advice))
        return -EINVAL;
    if (start & (PAGE_SIZE - 1))
        return -EINVAL;

    len = ALIGN_TO(len, PAGE_SIZE);

    if (start + len <= start)
        return -EINVAL;

    mutex_lock(&mm->vm_lock);
    ret = do_madvise_walk(mm, start, len, advice);
    mutex_unlock(&mm->vm_lock);
    return ret;
}
