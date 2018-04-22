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
#include <onyx/vmm.h>
#include <onyx/pagecache.h>
#include <onyx/utils.h>

static spinlock_t block_list_lock = {0};
static struct page_cache_block *block_list = NULL;

struct page *allocate_cache_block(void)
{
	struct page *p = get_phys_page();
	return p;
}

void __add_to_list(struct page_cache_block *b)
{
	acquire_spinlock(&block_list_lock);

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

	release_spinlock(&block_list_lock);
}
struct page_cache_block *add_to_cache(void *data, size_t size, off_t offset, struct inode *file)
{
	/* Allocate a block/page for the cache */
	struct page *page = allocate_cache_block();
	if(!page)
		return errno = ENOMEM, NULL;
	
	/* Get a mapping for the physical page */
	void *buffer = PHYS_TO_VIRT(page->paddr);

	/* 
	 * Do note that currently, PHYS_TO_VIRT cannot return NULL as it cannot
	 * fail, so this is effectively dead code that might be needed in some
	 * future architecture that the kernel may run on. 
	*/
	if(!buffer)
	{
		free_page(page);
		return NULL;
	}

	memcpy(buffer, data, size);
	struct page_cache_block *c = zalloc(sizeof(struct page_cache_block));
	if(!c)
	{
		free_page(page);
		return errno = ENOMEM, NULL;
	}

	c->buffer = buffer;
	c->page = page;
	c->node = file;
	c->size = size;
	c->offset = offset;

	__add_to_list(c);
	return c;
}

size_t __do_vfs_write(void *buf, size_t size, off_t off, struct inode *this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return __do_vfs_write(buf, size, off, this->link);
	if(this->fops.write != NULL)
		return this->fops.write(off, size, buf, this);

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

void wakeup_sync_thread()
{
	thread_wake_up(sync_thread);
}
