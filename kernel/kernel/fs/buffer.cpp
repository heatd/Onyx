/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <stdio.h>

#include <onyx/block.h>
#include <onyx/buffer.h>
#include <onyx/cpu.h>
#include <onyx/filemap.h>
#include <onyx/mm/flush.h>
#include <onyx/mm/slab.h>

#include <uapi/fcntl.h>

static struct slab_cache *buffer_cache = nullptr;

__init static void buffer_cache_init()
{
    buffer_cache = kmem_cache_create("block_buf", sizeof(block_buf), 0, 0, nullptr);
    CHECK(buffer_cache != nullptr);
}

static void buffer_writepage_end(struct bio_req *req)
{
    struct page *page = req->vec[0].page;
    DCHECK(page != nullptr);
    page_end_writeback(page, (struct inode *) req->b_private);
}

ssize_t buffer_writepage(struct page *page, size_t offset, struct inode *ino) REQUIRES(page)
    RELEASE(page)
{
    auto blkdev = reinterpret_cast<blockdev *>(ino->i_helper);
    DCHECK(blkdev != nullptr);

    auto bufs = reinterpret_cast<block_buf *>(page->priv);
    block_buf *first_dirty = nullptr, *last_dirty = nullptr;

    /* Let's find the dirtied range in the page */
    for (block_buf *it = bufs; it != nullptr; it = it->next)
    {
        if (it->flags & BLOCKBUF_FLAG_DIRTY)
        {
            if (!first_dirty)
                first_dirty = it;
            last_dirty = it;
            bb_clear_flag(it, BLOCKBUF_FLAG_DIRTY);
        }
    }

    if (!first_dirty)
    {
        // HACK! Take the first and last buffers of the page
        for (block_buf *it = bufs; it != nullptr; it = it->next)
        {
            if (!first_dirty)
                first_dirty = it;
            last_dirty = it;
        }
    }

    DCHECK(first_dirty != nullptr);
    DCHECK(last_dirty != nullptr);

    sector_t disk_sect = (first_dirty->block_nr * first_dirty->block_size) / blkdev->sector_size;

    struct bio_req *r = bio_alloc(GFP_NOIO, 1);
    if (!r)
    {
        unlock_page(page);
        return -EIO;
    }

    r->sector_number = disk_sect;
    r->flags = BIO_REQ_WRITE_OP;
    r->b_end_io = buffer_writepage_end;
    r->b_private = ino;

    struct page_iov &vec = r->vec[0];
    vec.length = ((last_dirty->block_nr + 1) - first_dirty->block_nr) * first_dirty->block_size;
    vec.page_off = first_dirty->page_off;
    vec.page = first_dirty->this_page;

    page_start_writeback(page, ino);

    unlock_page(page);

    if (bio_submit_request(blkdev, r) < 0)
    {
        bio_put(r);
        return -EIO;
    }

    bio_put(r);

#if 0
	printk("Flushed #%lu[sector %lu].\n", buf->block_nr, disk_sect);
#endif

    return ((last_dirty->block_nr + 1) - first_dirty->block_nr) * first_dirty->block_size;
}

block_buf *block_buf_from_page(struct page *p)
{
    return reinterpret_cast<block_buf *>(p->priv);
}

bool page_has_dirty_bufs(struct page *p)
{
    auto buf = reinterpret_cast<block_buf *>(p->priv);
    bool has_dirty_buf = false;

    while (buf)
    {
        if (buf->flags & BLOCKBUF_FLAG_DIRTY)
        {
            has_dirty_buf = true;
            break;
        }

        buf = buf->next;
    }

    return has_dirty_buf;
}

bool page_has_writeback_bufs(struct page *p)
{
    auto buf = reinterpret_cast<block_buf *>(p->priv);
    bool has_wb_buf = false;

    while (buf)
    {
        if (buf->flags & BLOCKBUF_FLAG_WRITEBACK)
        {
            has_wb_buf = true;
            break;
        }

        buf = buf->next;
    }

    return has_wb_buf;
}

struct block_buf *page_add_blockbuf(struct page *page, unsigned int page_off)
{
    assert(page->flags & PAGE_FLAG_BUFFER);
    DCHECK(page_locked(page));

    auto buf = (struct block_buf *) kmem_cache_alloc(buffer_cache, GFP_KERNEL);
    if (!buf)
    {
        return nullptr;
    }

    buf->page_off = page_off;
    buf->this_page = page;
    buf->next = nullptr;
    buf->refc = 1;
    buf->flags = 0;
    buf->assoc_buffers_obj = nullptr;
    spinlock_init(&buf->pagestate_lock);

    /* It's better to do this naively using O(n) as to keep memory usage per-struct page low. */
    /* We're not likely to hit substancial n's anyway */
    block_buf **pp = reinterpret_cast<block_buf **>(&page->priv);

    while (*pp)
        pp = &(*pp)->next;

    *pp = buf;

    return buf;
}

void block_buf_remove(struct block_buf *buf)
{
    struct page *page = buf->this_page;

    block_buf **pp = reinterpret_cast<block_buf **>(&page->priv);

    while (*pp)
    {
        block_buf *b = *pp;
        if (b == buf)
        {
            *pp = buf->next;
            break;
        }

        pp = &(*pp)->next;
    }
}

void block_buf_sync(struct block_buf *buf)
{
    /* TODO: Only write *this* buffer, instead of the whole page */
    struct page *page = buf->this_page;
    lock_page(page);
    buffer_writepage(page, page->pageoff << PAGE_SHIFT, buf->dev->b_ino);
    page_wait_writeback(page);
}

void block_buf_free(struct block_buf *buf)
{
    if (buf->flags & BLOCKBUF_FLAG_DIRTY)
        block_buf_sync(buf);

    /* TODO: I'm not sure if this is totally safe... think through it a bit more, once this is
     * actually a likely case (when page reclamation becomes a thing).
     */
    while (buf->assoc_buffers_obj)
    {
        struct vm_object *obj = buf->assoc_buffers_obj;
        scoped_lock g{obj->private_lock};

        if (buf->assoc_buffers_obj == obj)
        {
            list_remove(&buf->assoc_buffers_node);
            break;
        }
    }

    block_buf_remove(buf);

    kmem_cache_free(buffer_cache, buf);
}

void page_destroy_block_bufs(struct page *page)
{
    DCHECK(page_flag_set(page, PAGE_FLAG_BUFFER));
    auto b = reinterpret_cast<block_buf *>(page->priv);

    block_buf *next = nullptr;

    while (b)
    {
        next = b->next;

        block_buf_free(b);

        b = next;
    }
}

/* Hmmm - I don't like this. Like linux, We're limiting ourselves to
 * block_size <= page_size here...
 */

ssize_t bbuffer_readpage(struct page *p, size_t off, struct inode *ino)
{
    p->flags |= PAGE_FLAG_BUFFER;
    p->priv = 0;

    auto blkdev = reinterpret_cast<blockdev *>(ino->i_helper);
    DCHECK(blkdev != nullptr);

    sector_t sec_nr = off / blkdev->sector_size;

    if (off % blkdev->sector_size)
    {
        printf("bbuffer_readpage: Cannot read unaligned offset %lu\n", off);
        return -EIO;
    }

    auto block_size = blkdev->block_size;

    struct bio_req *r = bio_alloc(GFP_NOIO, 1);
    if (!r)
        return -EIO;
    r->sector_number = sec_nr;
    r->flags = BIO_REQ_READ_OP;
    struct page_iov &vec = r->vec[0];
    vec.length = PAGE_SIZE;
    vec.page = p;
    vec.page_off = 0;

    auto nr_blocks = PAGE_SIZE / block_size;
    size_t starting_block_nr = off / block_size;

    size_t curr_off = 0;

    int iost = bio_submit_req_wait(blkdev, r);
    bio_put(r);
    if (iost < 0)
        return iost;

    for (size_t i = 0; i < nr_blocks; i++)
    {
        struct block_buf *b;
        if (!(b = page_add_blockbuf(p, curr_off)))
        {
            page_destroy_block_bufs(p);
            return -ENOMEM;
        }

        b->block_nr = starting_block_nr + i;
        b->block_size = block_size;
        b->dev = blkdev;

        curr_off += block_size;
    }

    p->flags |= PAGE_FLAG_UPTODATE;
    return PAGE_SIZE;
}

/* We can be fairly liberal in stack usage here. 128 * 8 = 1024, so we're still ways off of the
 * stack limit. And the stack here is quite shallow, since sys_read -> read_iter_vfs ->
 * buffer_directio.
 */
#define INLINE_GPP_BATCH 128

static expected<struct bio_req *, int> iovec_to_bio(struct iovec_iter *iter, int op)
{
    /* We need total_bytes / PAGE_SIZE page_iovs. Unfortunately, we don't yet support page sg lists
     * with more than a single page. :(
     */
    const auto nr_vecs = iter->bytes / PAGE_SIZE;
    struct bio_req *req = bio_alloc(GFP_KERNEL, nr_vecs);
    if (!req)
        return unexpected{-ENOMEM};
    bio_set_pinned(req);

    const unsigned int gpp_flags = (op == DIRECT_IO_READ ? GPP_WRITE : 0) | GPP_USER;

    size_t i = 0;

    while (i < nr_vecs)
    {
        /* Fetch up to INLINE_GPP_BATCH pages at once. */
        struct page *batch[INLINE_GPP_BATCH];
        auto iov = iter->curiovec();
        size_t to_fetch = cul::min(vm_size_to_pages(iov.iov_len), (unsigned long) INLINE_GPP_BATCH);
        int result = get_phys_pages(iov.iov_base, gpp_flags, batch, to_fetch);
        if (result & (GPP_ACCESS_FAULT | GPP_ACCESS_PFNMAP))
        {
            /* If we found a fault OR PFNMAP, return -EINVAL (for PFNMAP) or -EFAULT (for unmapped
             * memory). */
            bio_put(req);
            return unexpected<int>{result & GPP_ACCESS_PFNMAP ? -EINVAL : -EFAULT};
        }

        DCHECK(i + to_fetch <= nr_vecs);
        for (size_t j = 0; j < to_fetch; j++)
        {
            struct page_iov &piov = req->vec[i + j];
            piov.page = batch[j];
            piov.page_off = 0;
            piov.length = PAGE_SIZE;

            if (j == 0)
            {
                /* If we're at the start of the iov, correctly add the page_off */
                piov.page_off = (unsigned long) iov.iov_base & (PAGE_SIZE - 1);
            }
            else if (j == to_fetch - 1)
            {
                /* If we're at the end, correctly set the length */
                piov.length = iov.iov_len & (PAGE_SIZE - 1);
                if (piov.length == 0)
                    piov.length = PAGE_SIZE;
            }
        }

        iter->advance(cul::min(iov.iov_len, (unsigned long) INLINE_GPP_BATCH << PAGE_SHIFT));
        i += to_fetch;
    }

    DCHECK(iter->empty());

    return req;
}

static ssize_t buffer_directio(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    struct inode *ino = filp->f_ino;
    blockdev *blkdev = reinterpret_cast<blockdev *>(ino->i_helper);
    DCHECK(blkdev != nullptr);
    int st;
    size_t to_read = iter->bytes;

    if (!iovec_is_aligned(iter, blkdev->sector_size))
        return -EINVAL;

    if (off & (blkdev->sector_size - 1))
        return -EINVAL;

    auto ex = iovec_to_bio(iter, DIRECT_IO_OP(flags));
    if (ex.has_error())
        return ex.error();

    struct bio_req *bio = ex.value();
    bio->sector_number = off / blkdev->sector_size;
    bio->flags |= (DIRECT_IO_OP(flags) == DIRECT_IO_READ ? BIO_REQ_READ_OP : BIO_REQ_WRITE_OP);
    st = bio_submit_req_wait(blkdev, bio);

    if (bio->flags & BIO_REQ_EIO)
        st = -EIO;

    bio_put(bio);
    if (st < 0)
        return st;

    return to_read;
}

static int block_prepare_write(struct inode *ino, struct page *page, size_t page_off, size_t offset,
                               size_t len)
{
    struct blockdev *bdev = (struct blockdev *) ino->i_helper;
    auto bdev_size = bdev->nr_sectors * bdev->sector_size;
    if (bdev_size <= offset + page_off || bdev_size < offset + page_off + len)
        return -EIO;
    return 0;
}

extern int bdev_on_open(struct file *f);
extern void bdev_release(struct file *f);
extern unsigned int blkdev_ioctl(int request, void *argp, struct file *f);

struct file_ops buffer_ops = {
    .ioctl = blkdev_ioctl,
    .on_open = bdev_on_open,
    .readpage = bbuffer_readpage,
    .writepage = buffer_writepage,
    .prepare_write = block_prepare_write,
    .release = bdev_release,
    .read_iter = filemap_read_iter,
    .write_iter = filemap_write_iter,
    .writepages = filemap_writepages,
    .fsyncdata = filemap_writepages,
    .directio = buffer_directio,
};

struct block_buf *sb_read_block(const struct superblock *sb, unsigned long block)
{
    struct blockdev *dev = sb->s_bdev;
    size_t real_off = sb->s_block_size * block;
    size_t aligned_off = real_off & -PAGE_SIZE;

    struct page *page;

    int st = filemap_find_page(dev->b_ino, real_off >> PAGE_SHIFT, 0, &page, nullptr);

    if (st < 0)
        return nullptr;

    auto buf = reinterpret_cast<block_buf *>(page->priv);

    while (buf && buf->block_nr != block)
    {
        buf = buf->next;
    }

    if (unlikely(!buf))
    {
        size_t page_off = real_off - aligned_off;
        sector_t aligned_block = aligned_off / sb->s_block_size;
#if 0
		printk("Aligned block: %lx\n", aligned_block);
		printk("Aligned off %lx real off %lx\n", aligned_off, real_off);
#endif
        sector_t block_nr = aligned_block + ((real_off - aligned_off) / sb->s_block_size);

        if (!(buf = page_add_blockbuf(page, page_off)))
        {
            page_unref(page);
            return nullptr;
        }

        buf->block_nr = block_nr;
        buf->block_size = sb->s_block_size;
        buf->dev = sb->s_bdev;
    }

    block_buf_get(buf);

    page_unref(page);

    return buf;
}

void block_buf_dirty(block_buf *buf)
{
    if (!bb_test_and_set(buf, BLOCKBUF_FLAG_DIRTY))
        return;
    struct page *page = buf->this_page;
    lock_page(page);
    filemap_mark_dirty(buf->dev->b_ino, page, buf->this_page->pageoff);
    unlock_page(page);
}

void page_remove_block_buf(struct page *page, size_t offset, size_t end)
{
    block_buf **pp = (block_buf **) &page->priv;

    while (*pp != nullptr)
    {
        if ((*pp)->page_off >= offset && (*pp)->page_off < end)
        {
            auto bbuf = *pp;
            *pp = (*pp)->next;
            block_buf_free(bbuf);
        }
        else
            pp = &(*pp)->next;
    }
}

/**
 * @brief Associate a block_buf with a vm_object
 * This is used for e.g indirect blocks that want to be written back
 * when doing fsync. The vm_object does *not* need to be the block device's.
 *
 * @param buf Block buf
 * @param object Object
 */
void block_buf_associate(struct block_buf *buf, struct vm_object *object)
{
    scoped_lock g{object->private_lock};
    DCHECK(buf->assoc_buffers_obj == object || buf->assoc_buffers_obj == nullptr);

    if (!buf->assoc_buffers_obj)
    {
        buf->assoc_buffers_obj = object;
        list_add_tail(&buf->assoc_buffers_node, &object->private_list);
    }
}

/**
 * @brief Sync all the associated buffers to this vm_object
 *
 * @param object VM object (of probably an fs's inode)
 */
void block_buf_sync_assoc(struct vm_object *object)
{
    spin_lock(&object->private_lock);
    // Progressively pop the head of the list, grab a ref (so we can't be moved away) and remove it
    // from the assoc buffers list, release the lock, sync the buffer, and do it all again.
    while (!list_is_empty(&object->private_list))
    {
        struct block_buf *bb = container_of(list_first_element(&object->private_list),
                                            struct block_buf, assoc_buffers_node);
        block_buf_get(bb);
        list_remove(&bb->assoc_buffers_node);
        bb->assoc_buffers_obj = nullptr;
        spin_unlock(&object->private_lock);

        if (bb->flags & BLOCKBUF_FLAG_DIRTY)
            block_buf_sync(bb);
        block_buf_put(bb);

        spin_lock(&object->private_lock);
    }

    spin_unlock(&object->private_lock);
}

/**
 * @brief Dirty a block buffer and associate it with an inode
 * The association will allow us to write this buffer back when syncing
 * the inode's data.
 *
 * @param buf Buffer to dirty
 * @param inode Inode to add it to
 */
void block_buf_dirty_inode(struct block_buf *buf, struct inode *inode)
{
    block_buf_dirty(buf);
    block_buf_associate(buf, inode->i_pages);
}

/**
 * @brief Tear down a vm object's assoc list
 *
 * @param object Object to tear down
 */
void block_buf_tear_down_assoc(struct vm_object *object)
{
    scoped_lock g{object->private_lock};
    list_for_every_safe (&object->private_list)
    {
        struct block_buf *bb = container_of(l, struct block_buf, assoc_buffers_node);
        bb->assoc_buffers_obj = nullptr;
        list_remove(&bb->assoc_buffers_node);
    }
}

/**
 * @brief Forget a block_buf's inode
 * This will remove it from the assoc list
 *
 * @param buf Buffer
 */
void block_buf_forget_inode(struct block_buf *buf)
{
    struct vm_object *obj = buf->assoc_buffers_obj;
    while (obj)
    {
        scoped_lock g{obj->private_lock};
        /* I think this covers all races against sync_assoc... */
        if (obj != buf->assoc_buffers_obj)
        {
            obj = buf->assoc_buffers_obj;
            continue;
        }

        list_remove(&buf->assoc_buffers_node);
        buf->assoc_buffers_obj = nullptr;
        break;
    }
}

void buffer_free_page(struct vm_object *vmo, struct page *page)
{
    if (page_flag_set(page, PAGE_FLAG_BUFFER))
        page_destroy_block_bufs(page);
    free_page(page);
}
