/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_MM_FLUSH_H
#define _ONYX_MM_FLUSH_H

#include <onyx/list.h>
#include <onyx/spinlock.h>
#include <onyx/semaphore.h>
#include <onyx/vm.h>
#include <onyx/pagecache.h>

/* TODO: This file started as mm specific but it's quite fs now, no? */

#ifndef __cplusplus

/* Keep C APIs here */

void flush_init(void);
void flush_add_page(struct page_cache_block *blk);
void flush_remove_page(struct page_cache_block *reg);

#else

#include <onyx/atomic.hpp>

namespace flush
{

class flush_dev
{
private:
	/* Each flush dev has a list of dirty pages that are backed by inodes that need flushing. */
	struct list_head dirty_pages;
	atomic<unsigned long> block_load;
	struct spinlock __lock;
	/* Each flush dev also is associated with a thread that runs every x seconds */
	struct thread *thread;
	struct semaphore thread_sem;
public:

	static constexpr unsigned long wb_run_delta_ms = 10000; 
	constexpr flush_dev() : dirty_pages{}, block_load{0}, __lock{}, thread{}, thread_sem{}
	{
		INIT_LIST_HEAD(&dirty_pages);
	}

	~flush_dev() {}

	unsigned long get_load()
	{
		return block_load;
	}

	void lock() { spin_lock_preempt(&__lock); }
	void unlock() { spin_unlock_preempt(&__lock); }

	void init();
	void run();
	void add_page(struct page_cache_block *block);
	void remove_page(struct page_cache_block *block);
	void sync();
};


};




#endif
#endif