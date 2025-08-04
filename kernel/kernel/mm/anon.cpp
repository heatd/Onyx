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
    struct vm_area_struct *vma = ctx->entry;
    struct fault_info *info = ctx->info;
    struct page *page = nullptr;
    pte_t *ptep;
    struct spinlock *lock;

    /* pte_present is done in do_wp_page, not here. */
    CHECK(!pte_present(ctx->oldpte));
    /* Permission checks have already been handled before .fault() */
    if (!info->write)
    {
        /* Don't copy, just fault the zero page */
        page = vm_get_zero_page();
        /* Write protect the page and don't bother flushing the TLB */
        ctx->page_rwx &= ~VM_WRITE;
    }
    else
    {
        struct anon_vma *anon = anon_vma_prepare(ctx->entry);
        if (!anon)
            return -ENOMEM;

        /* Allocate a brand-new, zero-filled page */
        page = alloc_page(GFP_KERNEL);
        if (!page)
            goto enomem;
        page_set_anon(page);
        page->owner = (struct vm_object *) anon;
        page->pageoff = ctx->vpage;
        page_add_lru(page);
        page_set_dirty(page);
    }

    if (pgtable_prealloc(vma->vm_mm, ctx->vpage) < 0)
        goto enomem;

    ptep = ptep_get_locked(vma->vm_mm, ctx->vpage, &lock);
    if (ptep->pte != ctx->oldpte.pte)
        goto out;

    increment_vm_stat(vma->vm_mm, resident_set_size, PAGE_SIZE);
    page_add_mapcount(page);
    set_pte(ptep, pte_mkpte((u64) page_to_phys(page),
                            calc_pgprot((u64) page_to_phys(page), ctx->page_rwx)));

out:
    spin_unlock(lock);
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
    shmemfs_sb = new tmpfs_superblock(0);
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
