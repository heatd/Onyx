/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_MM_WRITEBACK_H
#define _ONYX_MM_WRITEBACK_H

#include <onyx/list.h>
#include <onyx/spinlock.h>
#include <onyx/semaphore.h>
#include <onyx/vm.h>

#ifndef __cplusplus

/* Keep C APIs here */

void writeback_init(void);
void writeback_add_region(struct vm_region *reg);
void writeback_remove_region(struct vm_region *reg);

#else

#include <onyx/atomic.hpp>

namespace wb
{

class wb_block
{
private:
	/* Each WB block has a list of regions that are backed by inodes who need writeback. */
	struct list_head regions;
	atomic<unsigned long> block_load;
	struct spinlock __lock;
	/* Each WB block also is associated with a thread that runs every x seconds */
	struct thread *thread;
	struct semaphore thread_sem;
public:

	static constexpr unsigned long wb_run_delta_ms = 10000; 
	constexpr wb_block() : regions{}, block_load{0}, __lock{}, thread{}, thread_sem{}
	{
		INIT_LIST_HEAD(&regions);
	}

	~wb_block() {}

	unsigned long get_load()
	{
		return block_load;
	}

	void lock() { spin_lock_preempt(&__lock); }
	void unlock() { spin_unlock_preempt(&__lock); }

	void init();
	void run();
	void add_region(struct vm_region *reg);
	void remove_region(struct vm_region *reg);
};


};




#endif
#endif