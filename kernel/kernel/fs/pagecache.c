/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdatomic.h>

#include <onyx/compiler.h>
#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/task_switching.h>
#include <onyx/vm.h>
#include <onyx/pagecache.h>
#include <onyx/utils.h>
#include <onyx/condvar.h>
#include <onyx/mutex.h>
#include <onyx/init.h>

#include <onyx/mm/flush.h>

static atomic_size_t used_cache_pages = 0;

#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
uint32_t crc32_calculate(uint8_t *ptr, size_t len);
#endif

struct page_cache_block *add_to_cache(void *data, size_t size, size_t offset, struct inode *file)
{
	/* Allocate a block/page for the cache */
	struct page *page = data;

	struct page_cache_block *c = zalloc(sizeof(struct page_cache_block));
	if(!c)
	{
		free_page(page);
		return errno = ENOMEM, NULL;
	}

	c->buffer = PAGE_TO_VIRT(page);
	c->page = page;
	c->node = file;
	c->size = size;
	c->offset = offset;
	page->cache = c;
	used_cache_pages++;

#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
	c->integrity = crc32_calculate(c->buffer, c->size);
#endif

	return c;
}

void pagecache_dirty_block(struct page_cache_block *block)
{
	struct page *page = block->page;

	unsigned long old_flags = __sync_fetch_and_or(&page->flags, PAGE_FLAG_DIRTY);

	__sync_synchronize();

	if(old_flags & PAGE_FLAG_DIRTY)
		return;
	
	flush_add_page(block);
}

void pagecache_init(void)
{
	flush_init();
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(pagecache_init);

// FIXME: This never gets called
void page_cache_destroy(struct page_cache_block *block)
{
	// FIXME: Implement correctly
	free_page(block->page);
	used_cache_pages--;

	free(block);
}

size_t pagecache_get_used_pages(void)
{
	return used_cache_pages;
}
