/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdatomic.h>
#include <assert.h>

#include <kernel/dpc.h>
#include <kernel/vmm.h>
#include <kernel/irq.h>
#include <kernel/spinlock.h>
#include <kernel/scheduler.h>
#include <kernel/task_switching.h>
#include <kernel/slab.h>

/* The work queue does need locks for insertion, because another CPU might try to 
 * queue work at the same time as us */
static spinlock_t work_queue_locks[3];
static struct dpc_work *work_queues[3] = {0};
static volatile atomic_bool dpc_queue_is_empty = true;
static thread_t *dpc_thread = NULL;
static slab_cache_t *dpc_pool = NULL;

void dpc_do_work_on_workqueue(struct dpc_work *wq)
{
	while(wq)
	{
		wq->funcptr(wq->context);
		struct dpc_work *to_be_freed = wq;
		wq = wq->next;

		slab_free(dpc_pool, to_be_freed);
	}
}

void dpc_do_work(void *context)
{
	while(1)
	{
		/* Process work */
		for(int i = 0; i < 3; i++)
		{
			acquire_spinlock(&work_queue_locks[i]);

			/* Let's process DPC work */
			dpc_do_work_on_workqueue(work_queues[i]);
			
			/* Reset this queue */
			work_queues[i] = NULL;

			release_spinlock(&work_queue_locks[i]);
		}
		/* Now block if the queue is empty until another IRQ occurs */
		if(!work_queues[0] && !work_queues[1] && !work_queues[2])
			thread_set_state(dpc_thread, THREAD_BLOCKED);
	}
}

void dpc_init(void)
{
	dpc_thread = sched_create_thread(dpc_do_work, THREAD_KERNEL, NULL);
	assert(dpc_thread != NULL);
	dpc_thread->priority = 20;
	thread_set_state(dpc_thread, THREAD_BLOCKED);

	dpc_pool = slab_create("dpc", sizeof(struct dpc_work), 0, SLAB_FLAG_DONT_CACHE, NULL, NULL);
	assert(dpc_pool != NULL);

	assert(slab_populate(dpc_pool, DPC_POOL_NR_OBJS) != -1);
}

int dpc_schedule_work(struct dpc_work *_work, dpc_priority prio)
{
	/* We'll allocate a copy of the dpc_work, and if we fail, the IRQ simply isn't handled. 
	 * Note that we're only allocating memory here.
	*/
	struct dpc_work *work = slab_allocate(dpc_pool);
	if(!work)
		return -1;

	memcpy(work, _work, sizeof(struct dpc_work));
	acquire_spinlock(&work_queue_locks[prio]);

	if(!work_queues[prio])
		work_queues[prio] = work;
	else
	{
		struct dpc_work *w = work_queues[prio];
		while(w->next) w = w->next;
		w->next = work;
	}

	thread_set_state(dpc_thread, THREAD_RUNNABLE);
	release_spinlock(&work_queue_locks[prio]);

	return 0;
}
