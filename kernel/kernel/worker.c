/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <onyx/worker.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>
#include <onyx/mutex.h>
#include <onyx/panic.h>
#include <onyx/utils.h>
#include <onyx/init.h>

static thread_t *worker = NULL;
static struct mutex work_queue_mutex = MUTEX_INITIALIZER;
static struct work_request *work_queue = NULL;

void work_do_work(void* context)
{
	while(true)
	{
		mutex_lock(&work_queue_mutex);
		/* Do all the work needed */
		while(work_queue)
		{
			struct work_request *work = work_queue;
			work->func(work->param);
			work_queue = work_queue->next;
			free(work);
		}
	
		mutex_unlock(&work_queue_mutex);
		/* Set the thread state to sleeping and yield */
		set_current_state(THREAD_UNINTERRUPTIBLE);
		sched_yield();
	}
}

void worker_init(void)
{
	if(!(worker = sched_create_thread(work_do_work, 1, NULL)))
		panic("worker_init: Could not create the worker thread!\n");
	worker->priority = 20;

	sched_block(worker);
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(worker_init);

int worker_schedule(struct work_request *work, int priority)
{
	/* Create a duplicate of work(so we're able to easily free things) */
	work = memdup(work, sizeof(struct work_request));
	if(!work)
		return errno = ENOMEM, -1;
	
	mutex_lock(&work_queue_mutex);

	if(!work_queue)
	{
		work_queue = work;
		work->priority = priority;
		work->next = NULL;
	}
	else
	{
		struct work_request *queue = work_queue;
		while(queue->next && queue->priority >= priority) 
		{
			queue = queue->next;
		}
		struct work_request *next = queue->next;
		queue->next = work;
		work->next = next;
		work->priority = priority;
	}

	mutex_unlock(&work_queue_mutex);
	thread_wake_up(worker);
	return 0;
}
