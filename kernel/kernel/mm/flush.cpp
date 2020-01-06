/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <errno.h>

#include <onyx/scheduler.h>
#include <onyx/array.h>
#include <onyx/vfs.h>

#include <onyx/mm/flush.h>

static void flush_thr_init(void *arg);

namespace flush
{

static constexpr unsigned long nr_wb_threads = 4UL;
array<flush::flush_dev, nr_wb_threads> thread_list;

size_t __do_vfs_write(void *buf, size_t size, off_t off, struct inode *ino)
{
	if(ino->i_fops.write != NULL)
		return ino->i_fops.write(off, size, buf, ino);

	return -ENXIO;
}

void flush_dev::init()
{
	thread = sched_create_thread(flush_thr_init, THREAD_KERNEL, (void *) this);
	assert(thread != nullptr);
	sched_start_thread(thread);
}

void flush_dev::sync()
{
	lock();

	//printk("Syncing\n");
	/* We have to use list_for_every_safe because between clearing the page dirty
	 * flag and going to the next page some other cpu can see the flag is clear,
	 * and queue it up for another flush in another flush_dev(which isn't locked) */
	list_for_every_safe(&dirty_pages)
	{
		struct page_cache_block *blk = container_of(l, struct page_cache_block, dirty_list);
		/*printk("writeback file %p, size %lu, off %lu\n", blk->node,
			blk->size, blk->offset);*/

		__do_vfs_write(blk->buffer, blk->size, blk->offset, blk->node);

		__sync_fetch_and_and(&blk->page->flags, ~PAGE_FLAG_DIRTY);

		__sync_synchronize();
		
		struct page *page = blk->page;
		struct vm_object *vmo = blk->node->i_pages;
		vm_wp_page_for_every_region(page, vmo);
	}

	/* reset the list */
	list_reset(&dirty_pages);
	block_load = 0;

	unlock();
}

void flush_dev::run()
{
	while(true)
	{
		while(this->get_load())
		{
			sched_sleep(flush_dev::wb_run_delta_ms);

			//printk("Flushing data to disk\n");
			sync();
		}

		sem_wait(&thread_sem);
	}
}

void flush_dev::add_page(struct page_cache_block *reg)
{
	lock();

	list_add_tail(&reg->dirty_list, &dirty_pages);
	if(block_load++ == 0)
	{
		sem_signal(&thread_sem);
	}

	unlock();
}

void flush_dev::remove_page(struct page_cache_block *reg)
{
	lock();

	block_load--;

	list_remove(&reg->dirty_list);

	unlock();
}

}

void flush_thr_init(void *arg)
{
	flush::flush_dev *b = reinterpret_cast<flush::flush_dev *>(arg);
	b->run();
}

extern "C"
void flush_add_page(struct page_cache_block *page)
{
	flush::flush_dev *blk = nullptr;
	unsigned long load = ~0UL;

	for(auto &b : flush::thread_list)
	{
		if(b.get_load() < load)
		{
			load = b.get_load();
			blk = &b;
		}
	}

	/* wat */
	assert(blk != nullptr);
	
	blk->add_page(page);

	page->blk_list = (void *) blk;
}

extern "C"
void flush_remove_page(struct page_cache_block *blk)
{
	flush::flush_dev *b = (flush::flush_dev *) blk->blk_list;

	b->remove_page(blk);
}

extern "C"
void flush_init(void)
{
	for(auto &b : flush::thread_list)
	{
		b.init();
	}
}