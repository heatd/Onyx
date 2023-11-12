/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/filemap.h>
#include <onyx/mm/amap.h>
#include <onyx/pagecache.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#define FILEMAP_MARK_DIRTY RA_MARK_0

int filemap_find_page(struct inode *ino, size_t pgoff, unsigned int flags, struct page **outp)
{
    struct page *p = nullptr;
    int st = 0;
    vmo_status_t vst = vmo_get(ino->i_pages, pgoff << PAGE_SHIFT, 0, &p);
    if (vst != VMO_STATUS_OK)
    {
        if (vst == VMO_STATUS_BUS_ERROR)
            return -ERANGE;
        if (vst == VMO_STATUS_OUT_OF_MEM)
            return -ENOMEM;
        DCHECK(vst == VMO_STATUS_NON_EXISTENT);
        /* non existent! let's continue */
    }

    if (vst == VMO_STATUS_NON_EXISTENT)
    {
        if (flags & FIND_PAGE_NO_CREATE) [[unlikely]]
            return -ENOENT;
        if (!ino->i_fops->readpage) [[unlikely]]
        {
            /* If there's no way to bring it up to date, ENOENT */
            return -ENOENT;
        }

        /* Let's allocate a new page */
        p = alloc_page(GFP_KERNEL);
        if (!p)
            return -ENOMEM;
        p->owner = ino->i_pages;
        p->pageoff = pgoff;
        /* Add it in... */
        if (st = vmo_add_page(pgoff << PAGE_SHIFT, p, ino->i_pages); st < 0)
        {
            free_page(p);
            return st;
        }

        page_ref(p);

        /* Added! Just not up to date... */
    }

    /* If the page is not up to date, read it in, but first lock the page. All pages under IO have
     * the lock held.
     */
    if (!(p->flags & PAGE_FLAG_UPTODATE))
    {
        DCHECK(ino->i_fops->readpage != nullptr);

        lock_page(p);
        if (!(p->flags & PAGE_FLAG_UPTODATE))
        {
            ssize_t st2 = ino->i_fops->readpage(p, pgoff << PAGE_SHIFT, ino);

            /* In case of errors, propagate... */
            if (st2 < 0)
                st = st2;
        }

        if (flags & FIND_PAGE_LOCK)
            goto out;

        unlock_page(p);
    }

out:
    if (st == 0)
        *outp = p;
    else
    {
        if (p)
            page_unref(p);
    }

    return st;
}

ssize_t file_read_cache(void *buffer, size_t len, struct inode *file, size_t offset)
{
    if ((size_t) offset >= file->i_size)
        return 0;

    size_t read = 0;

    while (read != len)
    {
        struct page *page = nullptr;
        int st = filemap_find_page(file, offset >> PAGE_SHIFT, 0, &page);

        if (st < 0)
            return read ?: st;
        void *buf = PAGE_TO_VIRT(page);

        auto cache_off = offset % PAGE_SIZE;
        auto rest = PAGE_SIZE - cache_off;

        assert(rest > 0);

        size_t amount = len - read < (size_t) rest ? len - read : (size_t) rest;

        if (offset + amount > file->i_size)
        {
            amount = file->i_size - offset;
            if (copy_to_user((char *) buffer + read, (char *) buf + cache_off, amount) < 0)
            {
                page_unpin(page);
                return -EFAULT;
            }

            page_unpin(page);
            return read + amount;
        }
        else
        {
            if (copy_to_user((char *) buffer + read, (char *) buf + cache_off, amount) < 0)
            {
                page_unpin(page);
                return -EFAULT;
            }
        }

        offset += amount;
        read += amount;

        page_unpin(page);
    }

    return (ssize_t) read;
}

/**
 * @brief Read from a generic file (using the page cache) using iovec_iter
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Read bytes, or negative error code
 */
ssize_t filemap_read_iter(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    struct inode *ino = filp->f_ino;
    if ((size_t) off >= filp->f_ino->i_size)
        return 0;

    ssize_t st = 0;

    while (!iter->empty())
    {
        struct page *page = nullptr;
        int st2 = filemap_find_page(filp->f_ino, off >> PAGE_SHIFT, 0, &page);

        if (st2 < 0)
            return st ?: st2;
        void *buffer = PAGE_TO_VIRT(page);

        auto cache_off = off % PAGE_SIZE;
        auto rest = PAGE_SIZE - cache_off;

        /* Do not read more than i_size */
        if (off + rest > ino->i_size)
            rest = ino->i_size - off;

        /* copy_to_iter advances the iter automatically */
        ssize_t copied = copy_to_iter(iter, (const u8 *) buffer + cache_off, rest);
        page_unpin(page);

        if (copied <= 0)
            return st ?: copied;

        /* note: if copied < rest, we either faulted or ran out of len. in any case, it's handled */
        off += copied;
        st += copied;
    }

    return st;
}

/**
 * @brief Marks a page dirty in the filemap
 *
 * @param ino Inode to mark dirty
 * @param page Page to mark dirty
 * @param pgoff Page offset
 */
static void filemap_mark_dirty(struct inode *ino, struct page *page, size_t pgoff)
{
    if (ino->i_sb && ino->i_sb->s_flags & SB_FLAG_NODIRTY)
        return;
    if (!page_test_set_flag(page, PAGE_FLAG_DIRTY))
        return; /* Already marked as dirty, not our problem! */

    /* Set the DIRTY mark, for writeback */
    ino->i_pages->vm_pages.set_mark(pgoff, FILEMAP_MARK_DIRTY);

    inode_mark_dirty(ino, I_DATADIRTY);
}

ssize_t file_write_cache_unlocked(void *buffer, size_t len, struct inode *ino, size_t offset)
{
    // printk("File cache write %lu off %lu\n", len, offset);
    size_t wrote = 0;
    size_t pos = offset;

    while (wrote != len)
    {
        struct page *page = nullptr;
        int st = filemap_find_page(ino, offset >> PAGE_SHIFT, 0, &page);

        if (st < 0)
            return wrote ?: st;

        void *buf = PAGE_TO_VIRT(page);

        auto cache_off = offset & (PAGE_SIZE - 1);
        auto rest = PAGE_SIZE - cache_off;

        auto amount = len - wrote < rest ? len - wrote : rest;
        size_t aligned_off = offset & ~(PAGE_SIZE - 1);

        lock_page(page);

        if (st = ino->i_fops->prepare_write(ino, page, aligned_off, cache_off, amount); st < 0)
        {
            unlock_page(page);
            page_unpin(page);
            return st;
        }

        if (copy_from_user((char *) buf + cache_off, (char *) buffer + wrote, amount) < 0)
        {
            unlock_page(page);
            page_unpin(page);
            return -EFAULT;
        }

        filemap_mark_dirty(ino, page, offset >> PAGE_SHIFT);
        unlock_page(page);

        page_unpin(page);

        offset += amount;
        wrote += amount;
        pos += amount;

        // printk("pos %lu i_size %lu\n", pos, ino->i_size);

        // auto old_sz = ino->i_size;

        if (pos > ino->i_size)
            inode_set_size(ino, pos);

        /*if(old_sz != ino->i_size)
            printk("New size: %lu\n", ino->i_size);*/
    }

    return (ssize_t) wrote;
}

ssize_t file_write_cache(void *buffer, size_t len, struct inode *ino, size_t offset)
{
    scoped_rwlock<rw_lock::write> g{ino->i_rwlock};
    return file_write_cache_unlocked(buffer, len, ino, offset);
}

/**
 * @brief Write to a generic file (using the page cache) using iovec_iter
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Written bytes, or negative error code
 */
ssize_t filemap_write_iter(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    struct inode *ino = filp->f_ino;
    scoped_rwlock<rw_lock::write> g{ino->i_rwlock};

    ssize_t st = 0;

    while (!iter->empty())
    {
        struct page *page = nullptr;
        int st2 = filemap_find_page(filp->f_ino, off >> PAGE_SHIFT, 0, &page);

        if (st2 < 0)
            return st ?: st2;
        void *buffer = PAGE_TO_VIRT(page);

        auto cache_off = off % PAGE_SIZE;
        size_t aligned_off = off & -PAGE_SIZE;
        auto rest = PAGE_SIZE - cache_off;

        if (rest > iter->bytes)
            rest = iter->bytes;

        lock_page(page);

        if (st2 = ino->i_fops->prepare_write(ino, page, aligned_off, cache_off, rest); st2 < 0)
        {
            unlock_page(page);
            page_unpin(page);
            return st ?: st2;
        }

        /* copy_from_iter advances the iter automatically */
        ssize_t copied = copy_from_iter(iter, (u8 *) buffer + cache_off, rest);

        if (copied > 0)
            filemap_mark_dirty(ino, page, off >> PAGE_SHIFT);

        unlock_page(page);
        page_unpin(page);

        if (copied <= 0)
            return st ?: copied;

        /* note: if copied < rest, we either faulted or ran out of len. in any case, it's handled */
        off += copied;
        st += copied;

        if (off > ino->i_size)
            inode_set_size(ino, off);
    }

    return st;
}

int filemap_private_fault(struct vm_pf_context *ctx)
{
    struct vm_area_struct *region = ctx->entry;
    struct fault_info *info = ctx->info;
    struct page *page = nullptr;
    struct page *newp = nullptr;
    int st = 0;
    unsigned long pgoff = (ctx->vpage - region->vm_start) >> PAGE_SHIFT;

    /* Permission checks have already been handled before .fault() */
    if (region->vm_amap)
    {
        /* Check if the amap has any kind of page. It's possible we may need to CoW that */
        page = amap_get(region->vm_amap, pgoff);
    }

    if (!page)
    {
        st = filemap_find_page(region->vm_file->f_ino, (region->vm_offset >> PAGE_SHIFT) + pgoff, 0,
                               &page);

        if (st < 0)
            goto err;
    }

    if (!info->write)
    {
        /* Write-protect the page */
        ctx->page_rwx &= ~VM_WRITE;
        goto map;
    }

    /* write-fault, let's CoW the page */

    /* Lazily allocate the vm_amap struct */
    if (!region->vm_amap)
    {
        region->vm_amap = amap_alloc(vma_pages(region) << PAGE_SHIFT);
        if (!region->vm_amap)
            goto enomem;
    }

    /* Allocate a brand new page and copy the old page */
    newp = alloc_page(PAGE_ALLOC_NO_ZERO | GFP_KERNEL);
    if (!newp)
        goto enomem;

    copy_page_to_page(page_to_phys(newp), page_to_phys(page));

    if (amap_add(region->vm_amap, newp, region, pgoff, true) < 0)
    {
        free_page(newp);
        goto enomem;
    }

    page_unref(page);
    page = newp;

map:
    if (!vm_map_page(region->vm_mm, ctx->vpage, (u64) page_to_phys(page), ctx->page_rwx))
        goto enomem;

    /* Only unref if this page is not new. When we allocate a new page - because of CoW, amap_add
     * 'adopts' our reference. This works because amaps are inherently region-specific, and we have
     * the address_space locked.
     */
    if (!newp)
        page_unref(page);

    return 0;
enomem:
    st = -ENOMEM;
err:
    info->error_info = VM_SIGSEGV;
    if (page && !newp)
        page_unref(page);
    return st;
}

const struct vm_operations private_vmops = {.fault = filemap_private_fault};
