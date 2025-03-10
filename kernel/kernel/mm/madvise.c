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

#include "vma_internal.h"

static bool madvise_needs_write(int advice)
{
    switch (advice)
    {
        case MADV_DONTDUMP:
        case MADV_DODUMP:
            return true;
        default:
            return false;
    }
}

static bool madvise_valid_advice(int advice)
{
    switch (advice)
    {
        case MADV_DONTNEED:
        case MADV_DONTDUMP:
        case MADV_DODUMP:
            return true;
    }

    return false;
}

static int do_madvise_vma(struct vma_iterator *vmi, struct vm_area_struct *vma, unsigned long start,
                          unsigned long end, int advice)
{
    int new_vm_flags = vma->vm_flags;
    switch (advice)
    {
        case MADV_DONTNEED:
            return zap_page_range(start, end, vma);
        case MADV_DONTDUMP:
            new_vm_flags |= VM_DONTDUMP;
            break;
        case MADV_DODUMP:
            new_vm_flags &= ~VM_DONTDUMP;
            break;
        default:
            UNREACHABLE();
    }

    vma = vma_prepare_modify(vmi, vma, start, end);
    if (!vma)
        return -ENOMEM;
    vma->vm_flags = new_vm_flags;
    return 0;
}

static int do_madvise_walk(struct mm_address_space *mm, unsigned long start, size_t len, int advice)
{
    unsigned long limit = start + len;
    unsigned long last_vma_end = -1;
    int ret = -ENOMEM;
    struct vm_area_struct *vma;
    VMA_ITERATOR(vmi, mm, start, limit);

    mas_for_each(&vmi.mas, vma, vmi.end)
    {
        /* Break if we see a gap between VMAs, or if this vma is beyond limit */
        if (vma->vm_start >= limit)
            break;

        if (last_vma_end != -1UL && vma->vm_start != last_vma_end)
        {
            ret = -ENOMEM;
            break;
        }

        ret = do_madvise_vma(&vmi, vma, max(vma->vm_start, start), min(limit, vma->vm_end), advice);
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

    if (madvise_needs_write(advice))
        rw_lock_write(&mm->vm_lock);
    else
        rw_lock_read(&mm->vm_lock);

    ret = do_madvise_walk(mm, start, len, advice);

    if (madvise_needs_write(advice))
        rw_unlock_write(&mm->vm_lock);
    else
        rw_unlock_read(&mm->vm_lock);
    return ret;
}
