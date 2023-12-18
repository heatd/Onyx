/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
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

#include <onyx/mm/pool.hpp>

memory_pool<block_buf, 0> block_buf_pool;

ssize_t buffer_writepage(struct page *page, size_t offset, struct inode *ino)
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
        }
    }

    DCHECK(first_dirty != nullptr);

    sector_t disk_sect = (first_dirty->block_nr * first_dirty->block_size) / blkdev->sector_size;

    struct page_iov vec;
    vec.length = ((last_dirty->block_nr + 1) - first_dirty->block_nr) * first_dirty->block_size;
    vec.page_off = first_dirty->page_off;
    vec.page = first_dirty->this_page;

    struct bio_req r = {};
    r.nr_vecs = 1;
    r.sector_number = disk_sect;
    r.flags = BIO_REQ_WRITE_OP;

    r.vec = &vec;

    __atomic_fetch_or(&vec.page->flags, PAGE_FLAG_FLUSHING, __ATOMIC_RELAXED);

    if (bio_submit_request(blkdev, &r) < 0)
        return -EIO;
#if 0
	printk("Flushed #%lu[sector %lu].\n", buf->block_nr, disk_sect);
#endif

    return vec.length;
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

struct block_buf *page_add_blockbuf(struct page *page, unsigned int page_off)
{
    assert(page->flags & PAGE_FLAG_BUFFER);

    auto buf = block_buf_pool.allocate();
    if (!buf)
    {
        return nullptr;
    }

    buf->page_off = page_off;
    buf->this_page = page;
    buf->next = nullptr;
    buf->refc = 1;
    buf->flags = 0;

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

void block_buf_writeback(struct block_buf *buf)
{
    // flush_sync_one(&buf->flush_obj);
}

void block_buf_free(struct block_buf *buf)
{
    if (buf->flags & BLOCKBUF_FLAG_DIRTY)
        block_buf_writeback(buf);

    block_buf_remove(buf);

    block_buf_pool.free(buf);
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

    auto sb = blkdev->sb;

    assert(sb != nullptr);

    struct page_iov vec;
    vec.length = PAGE_SIZE;
    vec.page = p;
    vec.page_off = 0;

    struct bio_req r = {};
    r.nr_vecs = 1;
    r.vec = &vec;
    r.sector_number = sec_nr;
    r.flags = BIO_REQ_READ_OP;

    auto block_size = sb->s_block_size;
    auto nr_blocks = PAGE_SIZE / block_size;
    size_t starting_block_nr = off / block_size;

    size_t curr_off = 0;

    int iost = bio_submit_request(blkdev, &r);
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

struct file_ops buffer_ops = {
    .readpage = bbuffer_readpage,
    .writepage = buffer_writepage,
    .prepare_write = noop_prepare_write,
    .read_iter = filemap_read_iter,
    .write_iter = filemap_write_iter,
};

struct block_buf *sb_read_block(const struct superblock *sb, unsigned long block)
{
    struct blockdev *dev = sb->s_bdev;
    size_t real_off = sb->s_block_size * block;
    size_t aligned_off = real_off & -PAGE_SIZE;

    struct page *page;

    int st = filemap_find_page(dev->b_ino, real_off >> PAGE_SHIFT, 0, &page);

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
    /* XXX */
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
