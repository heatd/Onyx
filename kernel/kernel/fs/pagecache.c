/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/task_switching.h>
#include <onyx/vm.h>
#include <onyx/pagecache.h>
#include <onyx/utils.h>

static struct spinlock block_list_lock = {0};
static struct page_cache_block *block_list = NULL;

size_t __do_vfs_write(void *buf, size_t size, off_t off, struct inode *this);

struct page *allocate_cache_block(void)
{
	struct page *p = alloc_page(0);
	return p;
}

void __add_to_list(struct page_cache_block *b)
{
	spin_lock_preempt(&block_list_lock);

	struct page_cache_block **pp = &block_list;

	while(*pp)
		pp = &((*pp)->next);
	*pp = b;
	
	if(unlikely(pp == &block_list))
	{
		b->prev = NULL;
	}
	else
	{
		struct page_cache_block *p = container_of(pp,
			struct page_cache_block, next);
		b->prev = p;
	}

	spin_unlock_preempt(&block_list_lock);
}

static void remove_from_list(struct page_cache_block *b)
{
	spin_lock(&block_list_lock);

	/* Do a last flush in case it's dirty */
	if(b->dirty)
	{
		__do_vfs_write(b->buffer, b->size, b->offset, b->node);
	}

	/* Adjust the list */

	if(b->prev)
	{
		b->prev->next = b->next;
		if(b->next)
			b->next->prev = b->prev;
	}
	else
	{
		block_list = b->next;
		if(b->next)
			b->next->prev = NULL;
	}

	spin_unlock(&block_list_lock);
}

#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
uint32_t crc32_calculate(uint8_t *ptr, size_t len);
#endif

struct page_cache_block *add_to_cache(void *data, size_t size, off_t offset, struct inode *file)
{
	/* Allocate a block/page for the cache */
	struct page *page = data;

	struct page_cache_block *c = zalloc(sizeof(struct page_cache_block));
	if(!c)
	{
		free_page(page);
		return errno = ENOMEM, NULL;
	}

	c->buffer = PHYS_TO_VIRT(page->paddr);
	c->page = page;
	c->node = file;
	c->size = size;
	c->offset = offset;
	#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
	c->integrity = crc32_calculate(c->buffer, c->size);
	#endif

	__add_to_list(c);
	return c;
}

size_t __do_vfs_write(void *buf, size_t size, off_t off, struct inode *this)
{
	if(this->i_fops.write != NULL)
		return this->i_fops.write(off, size, buf, this);

	return errno = ENOSYS;
}

static thread_t *sync_thread;

void pagecache_do_run(void)
{
	struct page_cache_block *c = block_list;

	/* Go through every block and check if it's dirty */
	for(; c != NULL; c = c->next)
	{
		if(c->dirty)
		{
			printk("VFS write to inode %lu\n", c->node->i_inode);
			/* If so, write to the underlying fs */
			__do_vfs_write(c->buffer, c->size, c->offset, c->node);
			c->dirty = 0;
		}
	}
}
void pagecache_sync(void *arg)
{
	UNUSED(arg);

	/* 
	 * The pagecache daemon thread needs to loop forever and complete a run
	 * when it is woken up, or in other words, when a block has been
	 * written to and is marked dirty 
	*/
	for(;;)
	{
		pagecache_do_run();
		thread_set_state(sync_thread, THREAD_BLOCKED);
	}
}

void pagecache_init(void)
{
	sync_thread = sched_create_thread(pagecache_sync, 1, NULL);
	if(!sync_thread)
		panic("Could not spawn the sync thread!\n");
	thread_set_state(sync_thread, THREAD_BLOCKED);
}

void wakeup_sync_thread(void)
{
	thread_wake_up(sync_thread);
}

void page_cache_destroy(struct page_cache_block *block)
{
	remove_from_list(block);

	free_page(block->page);

	free(block);
}