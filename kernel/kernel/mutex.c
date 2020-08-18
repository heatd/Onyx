/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>

#include <onyx/mutex.h>
#include <onyx/scheduler.h>
#include <onyx/task_switching.h>
#include <onyx/thread.h>

void prepare_sleep_mutex(struct mutex *mtx, int state)
{
	struct thread *t = get_current_thread();
	
	set_current_state(state);

	list_add_tail(&t->wait_list_head, &mtx->thread_list);
}

void commit_sleep(void)
{
	sched_yield();
}

int mutex_lock_slow_path(struct mutex *mutex, int state)
{
	int ret = 0;
	bool signals_allowed = state == THREAD_INTERRUPTIBLE;

	struct thread *current = get_current_thread();

	unsigned long cpu_flags = spin_lock_irqsave(&mutex->llock);

	prepare_sleep_mutex(mutex, state);

	while(!__sync_bool_compare_and_swap(&mutex->counter, 0, 1))
	{
		if(signals_allowed && signal_is_pending())
		{
			ret = -EINTR;
			break;
		}

		assert(mutex->owner != current);

		spin_unlock_irqrestore(&mutex->llock, cpu_flags);

		commit_sleep();

		cpu_flags = spin_lock_irqsave(&mutex->llock);

		list_remove(&current->wait_list_head);

		prepare_sleep_mutex(mutex, state);
	}

	list_remove(&current->wait_list_head);

	set_current_state(THREAD_RUNNABLE);

	spin_unlock_irqrestore(&mutex->llock, cpu_flags);

	return ret;
}

int __mutex_lock(struct mutex *mutex, int state)
{
	int ret = 0;
	if(!__sync_bool_compare_and_swap(&mutex->counter, 0, 1))
		ret = mutex_lock_slow_path(mutex, state);

	mutex->owner = get_current_thread();

	return ret;
}

void mutex_lock(struct mutex *mutex)
{
	__mutex_lock(mutex, THREAD_UNINTERRUPTIBLE);
}

int mutex_lock_interruptible(struct mutex *mutex)
{
	return __mutex_lock(mutex, THREAD_INTERRUPTIBLE);
}

void mutex_unlock(struct mutex *mutex)
{
	mutex->owner = NULL;
	__sync_bool_compare_and_swap(&mutex->counter, 1, 0);
	__sync_synchronize();

	unsigned long cpu_flags = spin_lock_irqsave(&mutex->llock);

	if(!list_is_empty(&mutex->thread_list))
	{
		struct list_head *l = list_first_element(&mutex->thread_list);
		assert(l != &mutex->thread_list);
		struct thread *t = container_of(l, struct thread, wait_list_head);

		thread_wake_up(t);
	}

	spin_unlock_irqrestore(&mutex->llock, cpu_flags);
}

bool mutex_holds_lock(struct mutex *m)
{
	return m->counter == 1 && m->owner == get_current_thread();
}
