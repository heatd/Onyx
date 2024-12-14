/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/block.h>
#include <onyx/block/blk_plug.h>
#include <onyx/filemap.h>
#include <onyx/gen/trace_filemap.h>
#include <onyx/mm/page_lru.h>
#include <onyx/page.h>
#include <onyx/pagecache.h>
#include <onyx/readahead.h>
#include <onyx/rmap.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>
#include <onyx/vm_fault.h>

#include <uapi/fcntl.h>

int filemap_find_page(struct inode *ino, size_t pgoff, unsigned int flags, struct page **outp,
                      struct readahead_state *ra_state) NO_THREAD_SAFETY_ANALYSIS
{
    struct page *p = nullptr;
    int st = 0;
    vmo_status_t vst = VMO_STATUS_OK;
retry:
    vst = vmo_get(ino->i_pages, pgoff << PAGE_SHIFT, 0, &p);
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
        if (!ino->i_pages->ops->readpage) [[unlikely]]
        {
            /* If there's no way to bring it up to date, ENOENT */
            return -ENOENT;
        }

        /* Let's allocate a new page */
        p = alloc_page(PAGE_ALLOC_NO_ZERO | GFP_KERNEL);
        if (!p)
            return -ENOMEM;
        p->owner = ino->i_pages;
        p->pageoff = pgoff;
        /* Add it in... */
        struct page *p2 = vmo_add_page_safe(pgoff << PAGE_SHIFT, p, ino->i_pages);
        if (!p2)
        {
            page_unref(p);
            return -ENOMEM;
        }

        if (p == p2)
        {
            inc_page_stat(p, NR_FILE);
            page_ref(p);
            page_add_lru(p);
        }

        p = p2;

        /* Added! Just not up to date... */
    }
    else if (flags & FIND_PAGE_ACTIVATE)
    {
        /* Activate the page if need be. Note that we do not want to activate pages we create, to
         * help avoid the activation of access-once pages. */
        DCHECK(p != nullptr);
        page_promote_referenced(p);
    }

    if (!(flags & (FIND_PAGE_NO_READPAGE | FIND_PAGE_NO_RA)) && ra_state)
    {
        rw_lock_read(&ino->i_pages->truncate_lock);
        /* If we found PAGE_FLAG_READAHEAD, kick off more IO */
        if (page_flag_set(p, PAGE_FLAG_READAHEAD))
        {
            if (filemap_do_readahead_async(ino, ra_state, pgoff) != 1)
                __atomic_and_fetch(&p->flags, ~PAGE_FLAG_READAHEAD, __ATOMIC_RELAXED);
        }
        else if (!page_flag_set(p, PAGE_FLAG_UPTODATE))
        {
            /* Page is not up to date, kick off "synchronous" readahead. The code below will take
             * care of waiting for the IO, or kicking it off if required. */
            filemap_do_readahead_sync(ino, ra_state, pgoff);
            DCHECK(!(flags & FIND_PAGE_NO_READPAGE));
        }
        rw_unlock_read(&ino->i_pages->truncate_lock);
    }

    /* If the page is not up to date, read it in, but first lock the page. All pages under IO have
     * the lock held.
     */
    if (!(flags & FIND_PAGE_NO_READPAGE) && !page_flag_set(p, PAGE_FLAG_UPTODATE))
    {
        DCHECK(ino->i_pages->ops->readpage != nullptr);
        rw_lock_read(&ino->i_pages->truncate_lock);

        lock_page(p);
        if (p->owner != ino->i_pages)
        {
            unlock_page(p);
            page_unref(p);
            rw_unlock_read(&ino->i_pages->truncate_lock);
            goto retry;
        }

        if (!page_flag_set(p, PAGE_FLAG_UPTODATE))
        {
            ssize_t st2 = ino->i_pages->ops->readpage(p, pgoff << PAGE_SHIFT, ino);

            /* In case of errors, propagate... */
            if (st2 < 0)
                st = st2;
        }

        rw_unlock_read(&ino->i_pages->truncate_lock);

        if (flags & FIND_PAGE_LOCK)
            goto out;

        unlock_page(p);
    }

    if (flags & FIND_PAGE_LOCK)
    {
        lock_page(p);
        if (p->owner != ino->i_pages)
        {
            unlock_page(p);
            page_unref(p);
            goto retry;
        }
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
        int st = filemap_find_page(file, offset >> PAGE_SHIFT, FIND_PAGE_ACTIVATE, &page, nullptr);

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
    size_t size = ino->i_size;

    if (S_ISBLK(ino->i_mode))
    {
        struct blockdev *bdev = (struct blockdev *) ino->i_helper;
        size = bdev->nr_sectors * bdev->sector_size;
    }

    if (filp->f_flags & O_DIRECT)
        return filemap_do_direct(filp, off, iter, flags);

    ssize_t st = 0;

    while (!iter->empty())
    {
        struct page *page = nullptr;
        if ((size_t) off >= size)
            break;
        int st2 = filemap_find_page(filp->f_ino, off >> PAGE_SHIFT, FIND_PAGE_ACTIVATE, &page,
                                    &filp->f_ra_state);

        if (st2 < 0)
            return st ?: st2;
        void *buffer = PAGE_TO_VIRT(page);

        auto cache_off = off % PAGE_SIZE;
        auto rest = PAGE_SIZE - cache_off;

        /* Do not read more than i_size */
        if (off + rest > size)
            rest = size - off;

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

/* Spinlocks are not capabilities, yet... */
#undef EXCLUDES
#define EXCLUDES(...)

/**
 * @brief Marks a page dirty in the filemap
 *
 * @param page Page to mark dirty
 * @param pgoff Page offset
 * @invariant page is locked
 */
void filemap_mark_dirty(struct page *page, size_t pgoff) REQUIRES(page)
{
    DCHECK(page_locked(page));
    struct vm_object *object = page_vmobj(page);
    struct inode *ino = object->ino;

    // if (ino->i_sb && ino->i_sb->s_flags & SB_FLAG_NODIRTY)
    //     return;
    if (!page_test_set_flag(page, PAGE_FLAG_DIRTY))
        return; /* Already marked as dirty, not our problem! */

    if (ino)
        trace_filemap_dirty_page(ino->i_inode, ino->i_dev, pgoff);
    /* Set the DIRTY mark, for writeback */
    {
        scoped_lock g{object->page_lock};
        object->vm_pages.set_mark(pgoff, FILEMAP_MARK_DIRTY);
    }

    if (page_test_reclaim(page))
    {
        /* If we got a new dirty, this is probably not the best page to reclaim, even if we were/are
         * in the process. */
        page_clear_reclaim(page);
    }

    /* TODO: This is horribly leaky and horrible and awful but it stops NR_DIRTY from leaking on
     * tmpfs filesystems. I'll refrain from making a proper interface for this, because this really
     * needs the axe.
     */
    if (!ino || !inode_no_dirty(ino, I_DATADIRTY))
        inc_page_stat(page, NR_DIRTY);

    if (ino)
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
        int st = filemap_find_page(ino, offset >> PAGE_SHIFT, FIND_PAGE_ACTIVATE, &page, nullptr);

        if (st < 0)
            return wrote ?: st;

        void *buf = PAGE_TO_VIRT(page);

        auto cache_off = offset & (PAGE_SIZE - 1);
        auto rest = PAGE_SIZE - cache_off;

        auto amount = len - wrote < rest ? len - wrote : rest;
        size_t aligned_off = offset & ~(PAGE_SIZE - 1);

        lock_page(page);

        if (st = ino->i_pages->ops->prepare_write(ino, page, aligned_off, cache_off, amount);
            st < 0)
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

        filemap_mark_dirty(page, offset >> PAGE_SHIFT);
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

static int default_write_begin(struct file *filp, struct vm_object *vm_obj, off_t off, size_t len,
                               struct page **ppage) NO_THREAD_SAFETY_ANALYSIS
{
    struct page *page = nullptr;
    struct inode *ino = vm_obj->ino;
    int st = filemap_find_page(filp->f_ino, off >> PAGE_SHIFT, FIND_PAGE_ACTIVATE, &page,
                               &filp->f_ra_state);

    if (st < 0)
        return st;

    auto cache_off = off % PAGE_SIZE;
    size_t aligned_off = off & -PAGE_SIZE;
    auto rest = PAGE_SIZE - cache_off;

    if (rest > len)
        rest = len;

    lock_page(page);

    if (st = ino->i_pages->ops->prepare_write(ino, page, aligned_off, cache_off, rest); st < 0)
    {
        unlock_page(page);
        page_unpin(page);
        return st;
    }

    *ppage = page;
    return 0;
}

static int default_write_end(struct file *file, struct vm_object *vm_obj, off_t offset,
                             unsigned int written, unsigned int to_write,
                             struct page *page) NO_THREAD_SAFETY_ANALYSIS
{
    struct inode *ino = vm_obj->ino;
    unlock_page(page);
    page_unref(page);

    if (written > 0 && (size_t) offset + written > ino->i_size && !S_ISBLK(ino->i_mode))
        inode_set_size(ino, offset + written);
    return 0;
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
ssize_t filemap_write_iter(struct file *filp, size_t off, iovec_iter *iter,
                           unsigned int flags) NO_THREAD_SAFETY_ANALYSIS
{
    struct inode *ino = filp->f_ino;
    struct vm_object *vm_obj = ino->i_pages;

    if (filp->f_flags & O_DIRECT)
        return filemap_do_direct(filp, off, iter, DIRECT_IO_WRITE);

    scoped_rwlock<rw_lock::write> g{ino->i_rwlock};

    ssize_t st = 0;

    while (!iter->empty())
    {
        int st2;
        struct page *page;

        st2 = (vm_obj->ops->write_begin ?: default_write_begin)(filp, vm_obj, off, iter->bytes,
                                                                &page);
        if (st2 < 0)
            return st ?: st2;

        void *buffer = PAGE_TO_VIRT(page);
        unsigned int page_off = off - (page->pageoff << PAGE_SHIFT);
        unsigned int len = min(iter->bytes, PAGE_SIZE - page_off);
        /* copy_from_iter advances the iter automatically */
        ssize_t copied = copy_from_iter(iter, (u8 *) buffer + page_off, len);

        if (copied > 0)
            filemap_mark_dirty(page, off >> PAGE_SHIFT);

        st2 = (vm_obj->ops->write_end ?: default_write_end)(filp, vm_obj, off,
                                                            copied > 0 ? copied : 0, len, page);
        if (copied <= 0)
            return st ?: copied;
        if (st2 < 0)
            return st ?: st2;

        /* note: if copied < rest, we either faulted or ran out of len. in any case, it's handled */
        off += copied;
        st += copied;
    }

    return st;
}

static int filemap_get_tagged_pages(struct inode *inode, unsigned int mark, unsigned long start,
                                    unsigned long end, struct page **batch, unsigned int batchlen)
    EXCLUDES(inode->i_pages->page_lock)
{
    int batchidx = 0;
    scoped_lock g{inode->i_pages->page_lock};
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

void page_start_writeback(struct page *page) EXCLUDES(inode->i_pages->page_lock) REQUIRES(page)
{
    struct vm_object *obj = page_vmobj(page);
    scoped_lock g{obj->page_lock};
    obj->vm_pages.set_mark(page->pageoff, FILEMAP_MARK_WRITEBACK);
    page_set_writeback(page);
    page_ref(page);
    inc_page_stat(page, NR_WRITEBACK);
}

void page_end_writeback(struct page *page) EXCLUDES(inode->i_pages->page_lock)
{
    struct vm_object *obj = page_vmobj(page);
    spin_lock(&obj->page_lock);
    obj->vm_pages.clear_mark(page->pageoff, FILEMAP_MARK_WRITEBACK);
    spin_unlock(&obj->page_lock);
    page_clear_writeback(page);

    if (page_test_reclaim(page))
    {
        page_clear_reclaim(page);
        page_lru_demote_reclaim(page);
    }

    page_unref(page);
    dec_page_stat(page, NR_WRITEBACK);
}

void filemap_clear_dirty(struct page *page) REQUIRES(page)
{
    /* Clear the dirty flag for IO */
    struct vm_object *obj = page_vmobj(page);
    if (!page_test_clear_dirty(page))
        return;

    {
        scoped_lock g{obj->page_lock};
        obj->vm_pages.clear_mark(page->pageoff, FILEMAP_MARK_DIRTY);
    }

    /* Nothing to clear in PTEs if this is a swap page */
    if (!page_test_swap(page))
        vm_obj_clean_page(obj, page);
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
    struct blk_plug plug;
    blk_start_plug(&plug);

    while ((found = filemap_get_tagged_pages(inode, FILEMAP_MARK_DIRTY, start, wpinfo->end, &page,
                                             1)) > 0)
    {
        const unsigned long pageoff = page->pageoff;
        TRACE_EVENT_DURATION(filemap_writepage, ino, dev, pageoff);
        lock_page(page);

        if (page->owner != inode->i_pages)
        {
            /* Page must've been truncated, retry */
            unlock_page(page);
            page_unref(page);
            continue;
        }

        /* Start the next iteration from the following page */
        start = pageoff + 1;

        if (page_flag_set(page, PAGE_FLAG_WRITEBACK) || !page_flag_set(page, PAGE_FLAG_DIRTY))
        {
            unlock_page(page);
            page_unref(page);
            continue;
        }

        filemap_clear_dirty(page);

        ssize_t st = -EIO;

        if (inode->i_pages->ops->writepage)
            st = inode->i_pages->ops->writepage(inode->i_pages, page, pageoff << PAGE_SHIFT);
        else
        {
            /* Warn if we the inode we got doesn't have a valid writepage */
            __WARN();
        }

        if (st < 0)
        {
            /* Error! */
            page_unref(page);
            blk_end_plug(&plug);
            return st;
        }

        page_unref(page);
        page = nullptr;
    }

    blk_end_plug(&plug);

    if (wpinfo->flags & WRITEPAGES_SYNC)
    {
        /* We have previously kicked off IO, now wait for writeback */
        filemap_wait_writeback(inode, wpinfo->start, wpinfo->end);
    }

    return 0;
}

int filemap_fdatasync(struct inode *inode, unsigned long start, unsigned long end)
{
    DCHECK(inode->i_fops->fsyncdata);
    struct writepages_info wp;
    wp.start = start;
    wp.end = end;
    wp.flags = WRITEPAGES_SYNC;
    return inode->i_fops->fsyncdata(inode, &wp);
}

static int filemap_mkwrite_private(struct vm_pf_context *ctx,
                                   struct page *page) NO_THREAD_SAFETY_ANALYSIS
{
    struct page *newp = nullptr;
    struct anon_vma *anon = anon_vma_prepare(ctx->entry);
    if (!anon)
        return -ENOMEM;
    /* write-fault, let's CoW the page */

    if (0 && page_flag_set(page, PAGE_FLAG_ANON) && page_mapcount(page) == 1)
    {
        /* If this is an anon page *and* mapcount = 1, avoid allocating a new page. Since mapcount =
         * 1 (AND *ANON*), no one else can grab a ref. */
        /* TODO: We might be able to explore this - we may avoid the TLB shootdown and just change
         * prots, but it would require significant code refactoring as-is. */
        ctx->page = page;
        page_ref(page);
        return 0;
    }

    /* Allocate a brand new page and copy the old page */
    newp = alloc_page(PAGE_ALLOC_NO_ZERO | GFP_KERNEL);
    if (!newp)
        return -ENOMEM;
    page_set_anon(newp);
    newp->owner = (struct vm_object *) anon;
    newp->pageoff = ctx->vpage;
    page_add_lru(newp);

    copy_page_to_page(page_to_phys(newp), page_to_phys(page));
    page_set_dirty(newp);
    ctx->page = newp;
    return 0;
}

static int vm_prepare_write(struct inode *inode, struct page *p) REQUIRES(p)
{
    DCHECK_PAGE(page_locked(p), p);

    /* Correctness: We set the i_size before truncating pages from the page cache, so this should
     * not race... I think? */
    size_t i_size = inode->i_size;
    DCHECK(p->owner == inode->i_pages);
    size_t len = PAGE_SIZE;
    size_t offset = p->pageoff << PAGE_SHIFT;
    if (offset + PAGE_SIZE > i_size)
        len = i_size - offset;

    int st = inode->i_pages->ops->prepare_write(inode, p, offset, 0, len);
    filemap_mark_dirty(p, p->pageoff);
    return st;
}

static int filemap_mkwrite_shared(struct vm_pf_context *ctx,
                                  struct page *page) NO_THREAD_SAFETY_ANALYSIS
{
    struct vm_area_struct *vma = ctx->entry;
    ctx->page = page;
    return vm_prepare_write(vma->vm_file->f_ino, page);
}

static int filemap_fault(struct vm_pf_context *ctx) NO_THREAD_SAFETY_ANALYSIS
{
    struct vm_area_struct *vma = ctx->entry;
    struct fault_info *info = ctx->info;
    struct page *page = nullptr;
    struct inode *ino = vma->vm_file->f_ino;
    int st = 0;
    unsigned long pgoff = (ctx->vpage - vma->vm_start) >> PAGE_SHIFT;
    pte_t *ptep;
    pte_t oldpte = ctx->oldpte;
    struct spinlock *lock;

    /* We need to lock the page in case we're mapping it (that is, it's either a read-fault on
     * a private region, or any fault on a MAP_SHARED). */
    bool locked = (vma_private(vma) && !ctx->info->write) || vma_shared(vma);

    /* Permission checks have already been handled before .fault() */

    /* If a page was present, use that as the CoW source */
    if (vma_private(vma) && pte_present(oldpte))
    {
        page = phys_to_page(pte_addr(oldpte));
        DCHECK(info->write && !pte_write(oldpte));
    }

    if (!page)
    {
        unsigned long fileoff = (vma->vm_offset >> PAGE_SHIFT) + pgoff;
        if (ino->i_size <= (fileoff << PAGE_SHIFT))
        {
            info->signal = VM_SIGBUS;
            return -EIO;
        }

        unsigned ffp_flags = FIND_PAGE_ACTIVATE | (locked ? FIND_PAGE_LOCK : 0);
        st = filemap_find_page(vma->vm_file->f_ino, fileoff, ffp_flags, &page,
                               &vma->vm_file->f_ra_state);

        if (st < 0)
            goto err;
    }

    if (!info->write)
    {
        /* Write-protect the page */
        ctx->page_rwx &= ~VM_WRITE;
    }
    else
    {
        if (vma_private(vma))
        {
            DCHECK(!locked);
            st = filemap_mkwrite_private(ctx, page);
        }
        else
            st = filemap_mkwrite_shared(ctx, page);
        if (st < 0)
            goto err;
        /* We should invalidate the TLB if we had a mapping before. Note: I don't like that
         * we're mapping *over* the page, again. But it is what it is, and currently the code is
         * a little cleaner. */
        page = ctx->page;
        DCHECK(page != nullptr);
    }

    if (pgtable_prealloc(vma->vm_mm, ctx->vpage) < 0)
        goto enomem;

    ptep = ptep_get_locked(vma->vm_mm, ctx->vpage, &lock);
    if (ptep->pte != oldpte.pte)
    {
        /* Have to retry. Either this page is going away, or someone else nicely handled it for us.
         */
        goto out_unlock_pte;
    }

    if (ctx->page_rwx & VM_WRITE && !pte_none(oldpte) &&
        pte_addr(oldpte) == (unsigned long) page_to_phys(page))
    {
        /* Okay, logic is simple in case we're just toggling the W bit. This can happen for various
         * reasons, including mkwrite_private deciding we don't need to CoW, or a shared fault. In
         * this case, we can avoid doing a TLB shootdown. Doing a local TLB invalidation is okay. It
         * might result in spurious faults for other threads, but it's just way faster than
         * purposefully doing IPIs.
         */
        set_pte(ptep, pte_mkwrite(oldpte));
        tlbi_upgrade_pte_prots(vma->vm_mm, ctx->vpage);
    }
    else
    {
        /* New page. Just Map It. Sucks that we're copying this around... */
        struct page *oldp = NULL;
        if (!pte_present(oldpte))
            increment_vm_stat(vma->vm_mm, resident_set_size, PAGE_SIZE);

        page_add_mapcount(page);
        set_pte(ptep, pte_mkpte((u64) page_to_phys(page),
                                calc_pgprot((u64) page_to_phys(page), ctx->page_rwx)));

        if (unlikely(pte_present(oldpte) && !pte_special(oldpte)))
            oldp = phys_to_page(pte_addr(oldpte));

        /* We did our page table thing, now release the lock. We're going to need to IPI and it's
         * best we do it with no spinlock held.
         */
        spin_unlock(lock);

        if (pte_present(oldpte))
            vm_invalidate_range(ctx->vpage, 1);
        /* After the IPI we can sub the mapcount - which may involve some freeing here... */
        if (oldp)
            page_sub_mapcount(oldp);
        goto out;
    }

out_unlock_pte:
    spin_unlock(lock);
out:
    if (locked)
        unlock_page(page);
    page_unref(page);
    return 0;
enomem:
    st = -ENOMEM;
err:
    info->error_info = VM_SIGSEGV;
    if (locked && page)
        unlock_page(page);
    if (page)
        page_unref(page);
    return st;
}

const struct vm_operations file_vmops = {.fault = filemap_fault};
