/*
 * Copyright (c) 2023 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/dentry.h>
#include <onyx/mm/page_lru.h>
#include <onyx/mm/shmem.h>
#include <onyx/rmap.h>
#include <onyx/tmpfs.h>
#include <onyx/vm.h>
#include <onyx/vm_fault.h>

int vm_anon_fault(struct vm_pf_context *ctx);

const struct vm_operations anon_vmops = {.fault = vm_anon_fault};

int vm_anon_fault(struct vm_pf_context *ctx)
{
    struct vm_area_struct *region = ctx->entry;
    struct fault_info *info = ctx->info;
    struct page *page = nullptr, *oldp = nullptr;
    bool needs_invd = false;

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
        bool copy_old = false;
        if (pte_present(ctx->oldpte))
        {
            oldp = phys_to_page(pte_addr(ctx->oldpte));
            DCHECK(info->write && !pte_write(ctx->oldpte));
            if (oldp != vm_get_zero_page())
                copy_old = true;
            needs_invd = true;

            if (copy_old && 0 && page_flag_set(oldp, PAGE_FLAG_ANON) && page_mapcount(oldp) == 1)
            {
                /* If this is an anon page *and* mapcount = 1, avoid allocating a new page. Since
                 * mapcount = 1 (AND *ANON*), no one else can grab a ref. */
                /* TODO: We might be able to explore this - we may avoid the TLB shootdown and just
                 * change prots, but it would require significant code refactoring as-is. */
                /* TODO: checking mapcount = 1 probably isn't this easy once we get swapping,
                 * because refs may come and go. Will we need the page lock? */
                page = oldp;
                page_ref(page);
                goto map;
            }

            /* oldp's mapcount will be decremented in vm_map_page */
        }

        struct anon_vma *anon = anon_vma_prepare(ctx->entry);
        if (!anon)
            return -ENOMEM;

        /* Allocate a brand-new (possibly zero-filled) page */
        page = alloc_page((copy_old ? PAGE_ALLOC_NO_ZERO : 0) | GFP_KERNEL);
        if (!page)
            goto enomem;
        page_set_anon(page);
        page->owner = (struct vm_object *) anon;
        page->pageoff = ctx->vpage;
        page_add_lru(page);
        page_set_dirty(page);

        if (copy_old)
            copy_page_to_page(page_to_phys(page), page_to_phys(oldp));
        goto map;
    }

map:
    if (!vm_map_page(region->vm_mm, ctx->vpage, (u64) page_to_phys(page), ctx->page_rwx,
                     ctx->entry))
        goto enomem;
    if (needs_invd)
        vm_invalidate_range(ctx->vpage, 1);

    /* The mapcount holds the only reference we need for anon pages... */
    if (info->write)
        page_unref(page);
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
    dget(dentry);

    f = inode_to_file(ino);
    if (!f)
        goto err;

    f->f_dentry = dentry;
    return f;
err:
    if (dentry)
        dput(dentry);
    if (ino)
        inode_unref(ino);
    return nullptr;
}
