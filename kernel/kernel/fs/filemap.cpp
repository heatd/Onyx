/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/filemap.h>
#include <onyx/gen/trace_filemap.h>
#include <onyx/mm/amap.h>
#include <onyx/page.h>
#include <onyx/pagecache.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <uapi/fcntl.h>

int filemap_find_page(struct inode *ino, size_t pgoff, unsigned int flags,
                      struct page **outp) NO_THREAD_SAFETY_ANALYSIS
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

        inc_page_stat(p, NR_FILE);
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

static inline ssize_t filemap_do_direct(struct file *filp, size_t off, iovec_iter *iter,
                                        unsigned int flags)
{
    struct inode *ino = filp->f_ino;
    if (!ino->i_fops->directio)
        return -EIO;
    return ino->i_fops->directio(filp, off, iter, flags);
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

    if (filp->f_flags & O_DIRECT)
        return filemap_do_direct(filp, off, iter, flags);

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
 * @invariant page is locked
 */
void filemap_mark_dirty(struct inode *ino, struct page *page, size_t pgoff) REQUIRES(page)
{
    DCHECK(page_locked(page));
    // if (ino->i_sb && ino->i_sb->s_flags & SB_FLAG_NODIRTY)
    //     return;
    if (!page_test_set_flag(page, PAGE_FLAG_DIRTY))
        return; /* Already marked as dirty, not our problem! */

    trace_filemap_dirty_page(ino->i_inode, ino->i_dev, pgoff);
    /* Set the DIRTY mark, for writeback */
    {
        scoped_mutex g{ino->i_pages->page_lock};
        ino->i_pages->vm_pages.set_mark(pgoff, FILEMAP_MARK_DIRTY);
    }

    /* TODO: This is horribly leaky and horrible and awful but it stops NR_DIRTY from leaking on
     * tmpfs filesystems. I'll refrain from making a proper interface for this, because this really
     * needs the axe.
     */
    if (!inode_no_dirty(ino, I_DATADIRTY))
        inc_page_stat(page, NR_DIRTY);

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

    if (filp->f_flags & O_DIRECT)
        return filemap_do_direct(filp, off, iter, DIRECT_IO_WRITE);

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

static int filemap_get_tagged_pages(struct inode *inode, unsigned int mark, unsigned long start,
                                    unsigned long end, struct page **batch, unsigned int batchlen)
    EXCLUDES(inode->i_pages->page_lock)
{
    int batchidx = 0;
    scoped_mutex g{inode->i_pages->page_lock};
    radix_tree::cursor cursor =
        radix_tree::cursor::from_range_on_marks(&inode->i_pages->vm_pages, mark, start, end);

    while (!cursor.is_end())
    {
        if (!batchlen--)
            break;
        struct page *page = (struct page *) cursor.get();
        batch[batchidx++] = page;
        page_ref(page);
    }

    return batchidx;
}

void page_start_writeback(struct page *page, struct inode *inode)
    EXCLUDES(inode->i_pages->page_lock) REQUIRES(page)
{
    struct vm_object *obj = inode->i_pages;
    scoped_mutex g{obj->page_lock};
    obj->vm_pages.set_mark(page->pageoff, FILEMAP_MARK_WRITEBACK);
    page_set_writeback(page);
    page_ref(page);
    inc_page_stat(page, NR_WRITEBACK);
}

void page_end_writeback(struct page *page, struct inode *inode) EXCLUDES(inode->i_pages->page_lock)
{
    struct vm_object *obj = inode->i_pages;
    // TODO: Race!
    // scoped_mutex g{obj->page_lock};
    obj->vm_pages.clear_mark(page->pageoff, FILEMAP_MARK_WRITEBACK);
    page_clear_writeback(page);
    page_unref(page);
    dec_page_stat(page, NR_WRITEBACK);
}

static void page_clear_dirty(struct page *page) REQUIRES(page)
{
    /* Clear the dirty flag for IO */
    /* TODO: Add mmap walking and write-protect those mappings */
    struct vm_object *obj = page->owner;
    __atomic_and_fetch(&page->flags, ~PAGE_FLAG_DIRTY, __ATOMIC_RELEASE);
    scoped_mutex g{obj->page_lock};
    obj->vm_pages.clear_mark(page->pageoff, FILEMAP_MARK_DIRTY);
    /* TODO: I don't know if this (clearing the dirty mark *here*) is safe with regards to potential
     * sync()'s running at the same time.
     */
    dec_page_stat(page, NR_DIRTY);
}

static void filemap_wait_writeback(struct inode *inode, unsigned long start, unsigned long end)
{
    struct page *page;
    int found = 0;
    while ((found = filemap_get_tagged_pages(inode, FILEMAP_MARK_WRITEBACK, start, end, &page, 1)) >
           0)
    {
        const unsigned long pageoff = page->pageoff;
        /* Start the next iteration from the following page */
        start = pageoff + 1;
        page_wait_writeback(page);
        page_unref(page);
        page = nullptr;
    }
}

int filemap_writepages(struct inode *inode,
                       struct writepages_info *wpinfo) NO_THREAD_SAFETY_ANALYSIS
{
    /* NO_THREAD_SAFETY_ANALYSIS: function pointers don't have the appropriate RELEASE(page) */
    const ino_t ino = inode->i_inode;
    const dev_t dev = inode->i_dev;
    TRACE_EVENT_DURATION(filemap_writepages, ino, dev);
    unsigned long start = wpinfo->start;
    struct page *page;
    int found = 0;

    while ((found = filemap_get_tagged_pages(inode, FILEMAP_MARK_DIRTY, start, wpinfo->end, &page,
                                             1)) > 0)
    {
        const unsigned long pageoff = page->pageoff;
        /* Start the next iteration from the following page */
        start = pageoff + 1;

        TRACE_EVENT_DURATION(filemap_writepage, ino, dev, pageoff);
        lock_page(page);

        if (page_flag_set(page, PAGE_FLAG_WRITEBACK))
        {
            unlock_page(page);
            page_unref(page);
            continue;
        }

        page_clear_dirty(page);

        ssize_t st = inode->i_fops->writepage(page, pageoff << PAGE_SHIFT, inode);

        if (st < 0)
        {
            /* Error! */
            page_unref(page);
            return st;
        }

        page_unref(page);
        page = nullptr;
    }

    if (wpinfo->flags & WRITEPAGES_SYNC)
    {
        /* We have previously kicked off IO, now wait for writeback */
        filemap_wait_writeback(inode, wpinfo->start, wpinfo->end);
    }

    return 0;
}

int filemap_private_fault(struct vm_pf_context *ctx)
{
    struct vm_area_struct *region = ctx->entry;
    struct fault_info *info = ctx->info;
    struct page *page = nullptr;
    struct page *newp = nullptr;
    struct inode *ino = region->vm_file->f_ino;
    int st = 0;
    unsigned long pgoff = (ctx->vpage - region->vm_start) >> PAGE_SHIFT;
    bool amap = true;

    /* Permission checks have already been handled before .fault() */
    if (region->vm_amap)
    {
        /* Check if the amap has any kind of page. It's possible we may need to CoW that */
        page = amap_get(region->vm_amap, pgoff);
    }

    if (!page)
    {
        unsigned long fileoff = (region->vm_offset >> PAGE_SHIFT) + pgoff;
        amap = false;
        if (ino->i_size <= fileoff)
        {
            info->error_info = VM_SIGBUS;
            return -EIO;
        }

        st = filemap_find_page(region->vm_file->f_ino, fileoff, 0, &page);

        if (st < 0)
            goto err;
    }

    (void) amap;

#ifdef FILEMAP_PARANOID
    if (ctx->mapping_info & PAGE_PRESENT)
    {
        unsigned long mapped = MAPPING_INFO_PADDR(ctx->mapping_info);
        unsigned long fetched = (unsigned long) page_to_phys(page);
        if (mapped != fetched)
            panic("%s[%d]: filemap: Mapped page %lx != fetched %lx %s\n",
                  get_current_process()->name.data(), get_current_process()->pid_, mapped, fetched,
                  amap ? "from amap" : "from filemap");
    }
#endif
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
