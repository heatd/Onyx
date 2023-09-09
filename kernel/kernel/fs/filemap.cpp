/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/filemap.h>
#include <onyx/pagecache.h>
#include <onyx/vfs.h>

ssize_t file_read_cache(void *buffer, size_t len, struct inode *file, size_t offset)
{
    if ((size_t) offset >= file->i_size)
        return 0;

    size_t read = 0;

    while (read != len)
    {
        struct page_cache_block *cache = inode_get_page(file, offset);

        if (!cache)
            return read ?: -1;

        struct page *page = cache->page;

        auto cache_off = offset % PAGE_SIZE;
        auto rest = PAGE_SIZE - cache_off;

        assert(rest > 0);

        size_t amount = len - read < (size_t) rest ? len - read : (size_t) rest;

        if (offset + amount > file->i_size)
        {
            amount = file->i_size - offset;
            if (copy_to_user((char *) buffer + read, (char *) cache->buffer + cache_off, amount) <
                0)
            {
                page_unpin(page);
                return -EFAULT;
            }

            page_unpin(page);
            return read + amount;
        }
        else
        {
            if (copy_to_user((char *) buffer + read, (char *) cache->buffer + cache_off, amount) <
                0)
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
        struct page_cache_block *cache = inode_get_page(ino, off);

        if (!cache)
            return st ?: -EIO /* XXX err code is wrong */;

        struct page *page = cache->page;

        auto cache_off = off % PAGE_SIZE;
        auto rest = PAGE_SIZE - cache_off;

        /* Do not read more than i_size */
        if (off + rest > ino->i_size)
            rest = ino->i_size - off;

        /* copy_to_iter advances the iter automatically */
        ssize_t copied = copy_to_iter(iter, (const u8 *) cache->buffer + cache_off, rest);
        page_unpin(page);

        if (copied <= 0)
            return st ?: copied;

        /* note: if copied < rest, we either faulted or ran out of len. in any case, it's handled */
        off += copied;
        st += copied;
    }

    return st;
}

ssize_t file_write_cache_unlocked(void *buffer, size_t len, struct inode *ino, size_t offset)
{
    // printk("File cache write %lu off %lu\n", len, offset);
    size_t wrote = 0;
    size_t pos = offset;

    while (wrote != len)
    {
        struct page_cache_block *cache = inode_get_page(ino, offset, FILE_CACHING_WRITE);

        if (cache == nullptr)
        {
            int err = -errno;
            printk("Inode get page error offset %lu, size of inode %lu, vmo size %lu, err %d\n",
                   offset, ino->i_size, ino->i_pages->size, err);
            return wrote ?: err;
        }

        struct page *page = cache->page;

        auto cache_off = offset & (PAGE_SIZE - 1);
        auto rest = PAGE_SIZE - cache_off;

        auto amount = len - wrote < rest ? len - wrote : rest;
        size_t aligned_off = offset & ~(PAGE_SIZE - 1);

        lock_page(page);

        if (int st = ino->i_fops->prepare_write(ino, page, aligned_off, cache_off, amount); st < 0)
        {
            unlock_page(page);
            page_unpin(page);
            return st;
        }

        if (copy_from_user((char *) cache->buffer + cache_off, (char *) buffer + wrote, amount) < 0)
        {
            unlock_page(page);
            page_unpin(page);
            return -EFAULT;
        }

        if (cache->size < cache_off + amount)
        {
            cache->size = cache_off + amount;
        }

        pagecache_dirty_block(cache);
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
        struct page_cache_block *cache = inode_get_page(ino, off, FILE_CACHING_WRITE);

        if (!cache)
            return st ?: -EIO /* XXX err code is wrong */;

        struct page *page = cache->page;

        auto cache_off = off % PAGE_SIZE;
        size_t aligned_off = off & -PAGE_SIZE;
        auto rest = PAGE_SIZE - cache_off;

        if (rest > iter->bytes)
            rest = iter->bytes;

        lock_page(page);

        if (int st2 = ino->i_fops->prepare_write(ino, page, aligned_off, cache_off, rest); st2 < 0)
        {
            unlock_page(page);
            page_unpin(page);
            return st ?: st2;
        }

        /* copy_from_iter advances the iter automatically */
        ssize_t copied = copy_from_iter(iter, (u8 *) cache->buffer + cache_off, rest);

        if (copied > 0)
            pagecache_dirty_block(cache);
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
