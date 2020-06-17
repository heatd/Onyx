/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _PAGECACHE_H
#define _PAGECACHE_H

#include <onyx/mutex.h>
#include <onyx/paging.h>
#include <onyx/list.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <onyx/mm/flush.h>

struct page_cache_block
{
	/* Virtual mapping of the buffer */
	void *buffer;
	/* struct page of the buffer */
	struct page *page;

	struct inode *node;

	size_t size;

	size_t offset;
	
#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
	uint32_t integrity;
#endif

	struct flush_object fobj;
};

#define PAGE_CACHE_SIZE PAGE_SIZE
#define FILE_CACHING_WRITE	(1 << 0)

#ifdef __cplusplus
extern "C" {
#endif

struct page_cache_block *pagecache_create_cache_block(struct page *page, size_t size, size_t off, struct inode *node);
void pagecache_dirty_block(struct page_cache_block *block);
void pagecache_init(void);
void page_cache_destroy(struct page_cache_block *block);
size_t pagecache_get_used_pages(void);
ssize_t file_write_cache(void *buffer, size_t len, struct inode *file, size_t offset);
ssize_t file_read_cache(void *buffer, size_t len, struct inode *file, size_t off);

#ifdef __cplusplus
}
#endif

#endif
