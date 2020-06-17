/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>
#include <stdio.h>

#include <onyx/vfs.h>
#include <onyx/pagecache.h>
#include <onyx/page.h>
#include <onyx/vm.h>
#include <onyx/rwlock.h>
#include <onyx/panic.h>
#include <onyx/dev.h>

struct page_cache_block *inode_get_cache_block(struct inode *ino, size_t off, long flags)
{
	MUST_HOLD_LOCK(&ino->i_pages_lock);

	assert(ino->i_pages != nullptr);

	if(flags & FILE_CACHING_WRITE && off >= ino->i_pages->size)
	{
		ino->i_pages->size += (off - ino->i_pages->size) + PAGE_SIZE;
		struct page *p = alloc_page(0);
		if(!p)
			return nullptr;

		auto block = pagecache_create_cache_block(p, PAGE_SIZE, off, ino);
		if(!block)
		{
			free_page(p);
			return nullptr;
		}

		if(vmo_add_page(off, p, ino->i_pages) < 0)
		{
			page_cache_destroy(block);
			return nullptr;
		}

		page_pin(p);

		return block;

	}

	struct page *p = vmo_get(ino->i_pages, off, VMO_GET_MAY_POPULATE);
	if(!p)
		return nullptr;

	return p->cache;
}

struct page_cache_block *__inode_get_page_internal(struct inode *inode, size_t offset, long flags)
{
	size_t aligned_off = offset & -(PAGE_SIZE - 1);

	MUST_HOLD_LOCK(&inode->i_pages_lock);
	struct page_cache_block *b = inode_get_cache_block(inode, aligned_off, flags);
	
	return b;
}

struct page_cache_block *inode_get_page(struct inode *inode, size_t offset, long flags = 0)
{
	spin_lock_preempt(&inode->i_pages_lock);

	struct page_cache_block *b = __inode_get_page_internal(inode, offset, flags);

	/* No need to pin the page since it's already pinned by vmo_get */

	spin_unlock_preempt(&inode->i_pages_lock);

	return b;
}


extern "C"
ssize_t file_write_cache(void *buffer, size_t len, struct inode *ino, size_t offset)
{
	scoped_rwlock<rw_lock::write> g{ino->i_rwlock};

	size_t wrote = 0;
	size_t pos = offset;


	while(wrote != len)
	{
		struct page_cache_block *cache = inode_get_page(ino, offset, FILE_CACHING_WRITE);

		if(cache == nullptr)
			return wrote ?: -1;

		struct page *page = cache->page;

		auto cache_off = offset & (PAGE_SIZE - 1);
		auto rest = PAGE_SIZE - cache_off;

		auto amount = len - wrote < rest ? len - wrote : rest;

		if(copy_from_user((char *) cache->buffer + cache_off, (char*) buffer +
			wrote, amount) < 0)
		{
			page_unpin(page);
			errno = EFAULT;
			return -1;
		}
	
		if(cache->size < cache_off + amount)
		{
			cache->size = cache_off + amount;
		}

		pagecache_dirty_block(cache);

		page_unpin(page);
	
		offset += amount;
		wrote += amount;
		pos += amount;

		if(pos > ino->i_size)
			inode_set_size(ino, pos);
	}

	return (ssize_t) wrote;
}

extern "C"
ssize_t file_read_cache(void *buffer, size_t len, struct inode *file, size_t offset)
{
	if((size_t) offset >= file->i_size)
		return 0;

	size_t read = 0;

	while(read != len)
	{
		struct page_cache_block *cache = inode_get_page(file, offset);

		if(!cache)
			return read ?: -1;

		struct page *page = cache->page;

		auto cache_off = offset % PAGE_SIZE;
		auto rest = PAGE_SIZE - cache_off;

		assert(rest > 0);
	
		size_t amount = len - read < (size_t) rest ?
			len - read : (size_t) rest;

		if(offset + amount > file->i_size)
		{
			amount = file->i_size - offset;
			if(copy_to_user((char*) buffer + read, (char*) cache->buffer +
				cache_off, amount) < 0)
			{
				page_unpin(page);
				errno = EFAULT;
				return -1;
			}

			page_unpin(page);
			return read + amount;
		}
		else
		{
			if(copy_to_user((char*) buffer + read,  (char*) cache->buffer +
				cache_off, amount) < 0)
			{
				page_unpin(page);
				errno = EFAULT;
				return -1;
			}
		}

		offset += amount;
		read += amount;

		page_unpin(page);
	}

	return (ssize_t) read;
}

extern "C"
int inode_special_init(struct inode *ino)
{
	if(ino->i_type == VFS_TYPE_BLOCK_DEVICE || ino->i_type == VFS_TYPE_CHAR_DEVICE)
	{
		struct dev *d = dev_find(ino->i_rdev);
		if(!d)
			return -ENODEV;
		ino->i_fops = &d->fops;
		ino->i_helper = d->priv;
	}

	return 0;
}
