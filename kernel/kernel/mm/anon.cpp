/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/dentry.h>
#include <onyx/mm/amap.h>
#include <onyx/mm/shmem.h>
#include <onyx/tmpfs.h>
#include <onyx/vm.h>

int vm_anon_fault(struct vm_pf_context *ctx);

const struct vm_operations anon_vmops = {.fault = vm_anon_fault};

int vm_anon_fault(struct vm_pf_context *ctx)
{
    struct vm_area_struct *region = ctx->entry;
    struct fault_info *info = ctx->info;
    struct page *page = nullptr;
    unsigned long pgoff = (ctx->vpage - region->vm_start) >> PAGE_SHIFT;

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
            region->vm_amap = amap_alloc(vma_pages(region) << PAGE_SHIFT);
            if (!region->vm_amap)
                goto enomem;
        }

        /* Allocate a brand-new zero-filled page */
        page = alloc_page(GFP_KERNEL);
        if (!page)
            goto enomem;

        if (amap_add(region->vm_amap, page, region, pgoff, false) < 0)
        {
            free_page(page);
            goto enomem;
        }

        goto map;
    }

map:
    if (!vm_map_page(region->vm_mm, ctx->vpage, (u64) page_to_phys(page), ctx->page_rwx))
        goto enomem;

    return 0;
enomem:
    info->error_info = VM_SIGSEGV;
    return -ENOMEM;
}

static tmpfs_superblock *shmemfs_sb;

__init void shmem_init()
{
    shmemfs_sb = new tmpfs_superblock();
    CHECK(shmemfs_sb);
}

/**
 * @brief Create a new shmem file
 *
 * @param len Length, in bytes
 * @return Opened struct file, or NULL
 */
struct file *anon_get_shmem(size_t len)
{
    struct dentry *dentry;
    struct file *f;
    tmpfs_inode *ino = shmemfs_sb->alloc_inode(0777 | S_IFREG, 0);
    if (!ino)
        return nullptr;
    ino->i_size = -1UL;

    /* Note for future me: While this solution basically works, it does not properly work if we care
     * about merging of MAP_SHARED or mremap. That will take some more annoying codepaths that e.g
     * properly adjust the length of the inode.
     */
    dentry = dentry_create("[anon_shmem]", ino, nullptr);
    if (!dentry)
        goto err;

    f = inode_to_file(ino);
    if (!f)
        goto err;

    f->f_dentry = dentry;
    return f;
err:
    if (dentry)
        dentry_put(dentry);
    if (ino)
        inode_unref(ino);
    return nullptr;
}
