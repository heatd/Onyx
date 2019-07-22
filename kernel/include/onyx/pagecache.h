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

	volatile _Atomic long dirty;

	struct mutex lock;

	struct page_cache_block *prev;
	struct page_cache_block *next;
};

#define PAGE_CACHE_SIZE PAGE_SIZE

struct page_cache_block *add_to_cache(void *data, size_t size, size_t off, struct inode *node);
void pagecache_init(void);
void wakeup_sync_thread(void);
void page_cache_destroy(struct page_cache_block *block);

#endif
