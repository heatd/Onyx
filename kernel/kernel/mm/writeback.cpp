/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>

#include <onyx/scheduler.h>
#include <onyx/array.h>

#include <onyx/mm/writeback.h>

static void writeback_thr_init(void *arg);

namespace wb
{

static constexpr unsigned long nr_wb_threads = 4UL;
array<wb::wb_block, nr_wb_threads> thread_list;


void wb_block::init()
{
	thread = sched_create_thread(writeback_thr_init, THREAD_KERNEL, (void *) this);
	assert(thread != nullptr);
	sched_start_thread(thread);
}

void wb_block::run()
{
	while(true)
	{
		while(this->get_load())
		{
			sched_sleep(wb_block::wb_run_delta_ms);
			lock();

			printk("Hello\n");

			unlock();
		}

		sem_wait(&thread_sem);
	}
}

void wb_block::add_region(struct vm_region *reg)
{
	lock();

	list_add_tail(&reg->writeback_list, &regions);
	if(block_load++ == 0)
	{
		sem_signal(&thread_sem);
	}

	unlock();
}

void wb_block::remove_region(struct vm_region *reg)
{
	lock();

	block_load--;

	list_remove(&reg->writeback_list);

	unlock();
}

}

void writeback_thr_init(void *arg)
{
	wb::wb_block *b = reinterpret_cast<wb::wb_block *>(arg);
	b->run();
}

extern "C"
void writeback_add_region(struct vm_region *reg)
{
	wb::wb_block *blk = nullptr;
	unsigned long load = ~0UL;

	for(auto &b : wb::thread_list)
	{
		if(b.get_load() < load)
		{
			load = b.get_load();
			blk = &b;
		}
	}

	/* wat */
	assert(blk != nullptr);
	
	blk->add_region(reg);

	reg->wb_list = (void *) blk;
}

extern "C"
void writeback_remove_region(struct vm_region *reg)
{
	wb::wb_block *b = (wb::wb_block *) reg->wb_list;

	b->remove_region(reg);
}

extern "C"
void writeback_init(void)
{
	for(auto &b : wb::thread_list)
	{
		b.init();
	}
}