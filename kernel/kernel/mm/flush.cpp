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
	/* We have to use list_for_every_safe because between clearing the dirty
	 * flag and going to the next buf some other cpu can see the flag is clear,
	 * and queue it up for another flush in another flush_dev (which isn't locked) */
	list_for_every_safe(&dirty_bufs)
	{
		flush_object *buf = container_of(l, flush_object, dirty_list);
		/*printk("writeback file %p, size %lu, off %lu\n", blk->node,
			blk->size, blk->offset);*/

		buf->ops->flush(buf);

		buf->ops->set_dirty(false, buf);

		block_load--;
	}

	list_for_every_safe(&dirty_inodes)
	{
		struct inode *ino = container_of(l, struct inode, i_dirty_inode_node);

		__sync_fetch_and_and(&ino->i_flags, ~INODE_FLAG_DIRTY);
		__sync_synchronize();

		inode_flush(ino);
		block_load--;
	}

	/* reset the list */
	list_reset(&dirty_bufs);
	list_reset(&dirty_inodes);
	assert(block_load == 0);

	unlock();
}

ssize_t flush_dev::sync_one(struct flush_object *obj)
{
	lock();

	size_t res = obj->ops->flush(obj);

	obj->ops->set_dirty(false, obj);

	list_remove(&obj->dirty_list);
	block_load--;

	unlock();

	return res;
}

void flush_dev::run()
{
	while(true)
	{
		while(this->get_load())
		{
			sched_sleep_ms(flush_dev::wb_run_delta_ms);

			//printk("Flushing data to disk\n");
			sync();
		}

		sem_wait(&thread_sem);
	}
}

bool flush_dev::called_from_sync()
{
	/* We detect this by testing if the current thread holds this lock */
	return mutex_holds_lock(&__lock);
}

bool flush_dev::add_buf(struct flush_object *obj)
{
	/* It's very possible the flush code is calling us from sync and trying to
	 * lock the flush dev would cause a deadlock. Therefore, we want to sync it ourselves right now.
	 */
	if(called_from_sync())
	{
		obj->ops->flush(obj);
		obj->ops->set_dirty(false, obj);
		return false;
	}

	lock();

	list_add_tail(&obj->dirty_list, &dirty_bufs);
	if(block_load++ == 0)
	{
		sem_signal(&thread_sem);
	}

	unlock();

	return true;
}

void flush_dev::remove_buf(struct flush_object *obj)
{
	lock();
	
	/* We do a last check here inside the lock to be sure it's actually still dirty */
	if(obj->ops->is_dirty(obj))
	{
		/* TODO: I'm not sure this is 100% safe, because it might've gotten dirtied again
		 * to a different flushdev(but in that case, should we be removing it anyways?).
		 * This also applies to remove_inode().
		*/
		block_load--;
		list_remove(&obj->dirty_list);
	}

	unlock();
}

void flush_dev::add_inode(struct inode *ino)
{
	lock();
	
	list_add_tail(&ino->i_dirty_inode_node, &dirty_inodes);

	if(block_load++ == 0)
	{
		sem_signal(&thread_sem);
	}

	unlock();
}

void flush_dev::remove_inode(struct inode *ino)
{
	lock();

	/* We do a last check here inside the lock to be sure it's actually still dirty */
	if(ino->i_flags & INODE_FLAG_DIRTY)
	{
		block_load--;
		list_remove(&ino->i_dirty_inode_node);
	}

	unlock();
}

}

void flush_thr_init(void *arg)
{
	flush::flush_dev *b = reinterpret_cast<flush::flush_dev *>(arg);
	b->run();
}

flush::flush_dev *flush_allocate_dev()
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

	return blk;
}

void flush_add_buf(struct flush_object *f)
{
	flush::flush_dev *blk = flush_allocate_dev();

	/* wat */
	assert(blk != nullptr);
	
	/* If we were flushed right away, we're going to want to avoid setting f->blk_list */
	if(!blk->add_buf(f))
		return;

	f->blk_list = (void *) blk;
}

void flush_remove_buf(struct flush_object *blk)
{
	flush::flush_dev *b = (flush::flush_dev *) blk->blk_list;

	b->remove_buf(blk);
}

void flush_init(void)
{
	for(auto &b : flush::thread_list)
	{
		b.init();
	}
}

void flush_add_inode(struct inode *ino)
{
	auto dev = flush_allocate_dev();

	ino->i_flush_dev = dev;

	dev->add_inode(ino);
}

void flush_remove_inode(struct inode *ino)
{
	auto dev = reinterpret_cast<flush::flush_dev *>(ino->i_flush_dev);

	dev->remove_inode(ino);

	ino->i_flush_dev = nullptr;
}

ssize_t flush_sync_one(struct flush_object *obj)
{
	flush::flush_dev *b = (flush::flush_dev *) obj->blk_list;

	return b->sync_one(obj);
}

void flush_do_sync()
{
	for(auto &w : flush::thread_list)
	{
		w.sync();
	}
}

extern "C"
void sys_sync()
{
	flush_do_sync();
}
