/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/mm/amap.h>
#include <onyx/vm.h>

int vm_anon_fault(struct vm_pf_context *ctx);

const struct vm_operations anon_vmops = {.fault = vm_anon_fault};

int vm_anon_fault(struct vm_pf_context *ctx)
{
    struct vm_region *region = ctx->entry;
    struct fault_info *info = ctx->info;
    struct page *page = nullptr;
    unsigned long pgoff = (ctx->vpage - region->base) >> PAGE_SHIFT;

    /* Permission checks have already been handled before .fault() */
    if (!info->write)
    {
        /* Don't copy, just fault the zero page */
        page = vm_get_zero_page();
        /* Write protect the page and don't bother flushing the TLB */
        ctx->page_rwx &= ~VM_WRITE;
        ctx->page_rwx |= VM_NOFLUSH;
        goto map;
    }
    else
    {
        /* Lazily allocate the vm_amap struct */
        if (!region->vm_amap)
        {
            region->vm_amap = amap_alloc(region->pages << PAGE_SHIFT);
            if (!region->vm_amap)
                goto enomem;
        }

        /* Allocate a brand-new zero-filled page */
        page = alloc_page(GFP_KERNEL);
        if (!page)
            goto enomem;

        if (amap_add(region->vm_amap, page, region, pgoff) < 0)
        {
            free_page(page);
            goto enomem;
        }

        goto map;
    }

map:
    if (!vm_map_page(region->mm, ctx->vpage, (u64) page_to_phys(page), ctx->page_rwx))
        goto enomem;

    return 0;
enomem:
    info->error_info = VM_SIGSEGV;
    return -ENOMEM;
}
