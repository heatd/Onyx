/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdatomic.h>
#include <assert.h>

#include <onyx/dpc.h>
#include <onyx/vm.h>
#include <onyx/irq.h>
#include <onyx/spinlock.h>
#include <onyx/scheduler.h>
#include <onyx/task_switching.h>
#include <onyx/slab.h>
#include <onyx/semaphore.h>

/* The work queue does need locks for insertion, because another CPU might try to 
 * queue work at the same time as us */
static struct spinlock work_queue_locks[3];
static struct dpc_work *work_queues[3] = {0};
static struct semaphore dpc_work_semaphore = {0};
static thread_t *dpc_thread = NULL;
static slab_cache_t *dpc_pool = NULL;

void dpc_do_work_on_workqueue(struct dpc_work **wq)
{
	while(*wq)
	{
		(*wq)->funcptr((*wq)->context);
		struct dpc_work *to_be_freed = *wq;
		*wq = (*wq)->next;

		slab_free(dpc_pool, to_be_freed);
	}
}

void dpc_do_work(void *context)
{
	while(1)
	{
		sem_wait(&dpc_work_semaphore);

		/* Process work */
		for(int i = 0; i < 3; i++)
		{
			/* Let's process DPC work */
			dpc_do_work_on_workqueue(&work_queues[i]);
		}
	}
}

void dpc_init(void)
{
	sem_init(&dpc_work_semaphore, 0);

	dpc_thread = sched_create_thread(dpc_do_work, THREAD_KERNEL, NULL);
	assert(dpc_thread != NULL);
	dpc_thread->priority = 20;
	
	dpc_pool = slab_create("dpc", sizeof(struct dpc_work), 0, SLAB_FLAG_DONT_CACHE, NULL, NULL);
	assert(dpc_pool != NULL);

	assert(slab_populate(dpc_pool, 200) != -1);

	sched_start_thread(dpc_thread);
}

int dpc_schedule_work(struct dpc_work *_work, dpc_priority prio)
{
	/* We'll allocate a copy of the dpc_work, and if we fail, the IRQ simply isn't handled. 
	 * Note that we're only allocating memory here.
	*/
	struct dpc_work *work = slab_allocate(dpc_pool);
	if(!work)
	{
		printf("slab_allocate failed: dpc work request being discarded!\n");
		return -1;
	}

	memcpy(work, _work, sizeof(struct dpc_work));
	spin_lock(&work_queue_locks[prio]);

	if(!work_queues[prio])
	{
		work_queues[prio] = work;
	}
	else
	{
		struct dpc_work *w = work_queues[prio];
		while(w->next) w = w->next;
		w->next = work;
	}

	spin_unlock(&work_queue_locks[prio]);

	sem_signal(&dpc_work_semaphore);
	return 0;
}
