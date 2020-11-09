/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>

#include <onyx/rwlock.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>

#include "primitive_generic.h"

bool rw_lock_tryread(rwlock *lock)
{
	unsigned long l;
	unsigned long to_insert;

	do
	{
		l = lock->lock;
		if(l == RDWR_LOCK_WRITE - 1)
			return errno = EAGAIN, false;
		if(l == RDWR_LOCK_WRITE)
			return errno = EBUSY, false;

		to_insert = l + 1;
	} while(!__atomic_compare_exchange_n(&lock->lock, &l, to_insert, false,
	                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));

	return true;
}

bool rw_lock_trywrite(rwlock *lock)
{
	unsigned long expected = 0;
	unsigned long write_value = RDWR_LOCK_WRITE;
	return __atomic_compare_exchange_n(&lock->lock, &expected, write_value, false,
	                                   __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static void commit_sleep()
{
	sched_yield();
}

static void rwlock_prepare_sleep(rwlock *rwl, int state)
{
	scoped_lock g{rwl->llock};

	auto t = get_current_thread();
	
	set_current_state(state);

	list_add_tail(&t->wait_list_head, &rwl->waiting_list);
}

static void dequeue_thread_rwlock(rwlock *lock, thread *thread)
{
	scoped_lock g{lock->llock};

	list_remove(&thread->wait_list_head);
}

int __rw_lock_write(rwlock *lock, int state)
{
	/* Try once before doing the whole preempt disable loop and all */
	if(rw_lock_trywrite(lock))
		return 0;

	int ret = 0;
	thread *current = get_current_thread();

	bool signals_allowed = state == THREAD_INTERRUPTIBLE;

	rwlock_prepare_sleep(lock, state);

	while(!rw_lock_trywrite(lock))
	{
		if(signals_allowed && signal_is_pending())
		{
			ret = -EINTR;
			break;
		}

		commit_sleep();

		dequeue_thread_rwlock(lock, current);

		rwlock_prepare_sleep(lock, state);
	}

	dequeue_thread_rwlock(lock, current);

	set_current_state(THREAD_RUNNABLE);

	return ret;
}

int __rw_lock_read(rwlock *lock, int state)
{
	/* Try once before doing the whole preempt disable loop and all */
	if(rw_lock_tryread(lock))
		return 0;

	int ret = 0;
	thread *current = get_current_thread();

	bool signals_allowed = state == THREAD_INTERRUPTIBLE;

	rwlock_prepare_sleep(lock, state);

	while(!rw_lock_tryread(lock))
	{
		if(signals_allowed && signal_is_pending())
		{
			ret = -EINTR;
			break;
		}

		commit_sleep();

		dequeue_thread_rwlock(lock, current);

		rwlock_prepare_sleep(lock, state);
	}

	dequeue_thread_rwlock(lock, current);

	set_current_state(THREAD_RUNNABLE);

	return ret;
}

void rw_lock_write(rwlock *lock)
{
	__rw_lock_write(lock, THREAD_UNINTERRUPTIBLE);
}

int rw_lock_write_interruptible(rwlock *lock)
{
	return __rw_lock_write(lock, THREAD_INTERRUPTIBLE);
}

void rw_lock_read(rwlock *lock)
{
	__rw_lock_read(lock, THREAD_UNINTERRUPTIBLE);
}

int rw_lock_read_interruptible(rwlock *lock)
{
	return __rw_lock_read(lock, THREAD_INTERRUPTIBLE);
}

void rw_lock_wake_up_threads(rwlock *lock)
{
	scoped_lock g{lock->llock};

	list_for_every(&lock->waiting_list)
	{
		struct thread *t = container_of(l, thread, wait_list_head);

		thread_wake_up(t);
	}
}

void rw_lock_wake_up_thread(rwlock *lock)
{
	scoped_lock g{lock->llock};

	if(!list_is_empty(&lock->waiting_list))
	{
		struct list_head *l = list_first_element(&lock->waiting_list);
		assert(l != &lock->waiting_list);
		struct thread *t = container_of(l, thread, wait_list_head);

		thread_wake_up(t);
	}
}

void rw_unlock_read(rwlock *lock)
{
	/* Implementation note: If we're unlocking a read lock, only wake up a
	 * single thread, since the write lock is exclusive, like a mutex.
	*/
	if(__atomic_sub_fetch(&lock->lock, 1, __ATOMIC_RELEASE) == 0)
		rw_lock_wake_up_thread(lock);
}

void rw_unlock_write(rwlock *lock)
{
	__atomic_store_n(&lock->lock, 0, __ATOMIC_RELEASE);
	/* Implementation note: If we're unlocking a write lock, wake up every single thread
	 * because we can have both readers and writers waiting to get woken up.
	*/
	rw_lock_wake_up_threads(lock);
}

#ifdef CONFIG_KTEST_RWLOCK

#include <onyx/panic.h>
#include <onyx/cpu.h>
#include <libtest/libtest.h>

static volatile unsigned long counter = 0;
static rwlock rw_lock;
static unsigned int rw_alive_threads = 0;

static void rwlock_read(void *ctx)
{
	rw_alive_threads++;

	while(true)
	{
		rw_lock_read(&rw_lock);
		
		for(unsigned int i = 0; i < 0xffffff; i++)
		{
			unsigned long c0 = counter;

			for(unsigned int j = 0; j < 10; j++)
				cpu_relax();
			
			unsigned long c1 = counter;

			if(c1 != c0)
				panic("RwLock read lock broken");
		}

		unsigned long last_counter_read = counter;

		rw_unlock_read(&rw_lock);

		if(last_counter_read > 0x100000)
		{
			rw_alive_threads--;
			thread_exit();
		}
	}
}

void rwlock_write(void *__is_master)
{
	rw_alive_threads++;
	bool is_master = (bool) __is_master;

	while(true)
	{
		rw_lock_write(&rw_lock);
		
		for(unsigned int i = 0; i < 0xffffff; i++)
		{
			unsigned long c0 = counter;
			counter = counter + 1;

			for(unsigned int j = 0; j < 10; j++)
				cpu_relax();
			
			unsigned long c1 = counter;

			if(c1 != c0 + 1)
				panic("RwLock write lock broken");
		}

		unsigned long last_counter_read = counter;

		rw_unlock_write(&rw_lock);

		if(last_counter_read > 0x100000)
		{
			rw_alive_threads--;
			if(!is_master)
				thread_exit();
			else
				return;
		}
	}
}

bool rwlock_test(void)
{
	rw_alive_threads = 0;
	rwlock_init(&rw_lock);

	counter = 0;

	/* This test runs using 2 reading threads and two writing threads, constantly
	 * hammering a counter variable and checking if it changed while the lock is being held.
	 */

	struct thread *write2 = sched_create_thread(rwlock_write, THREAD_KERNEL, NULL);
	assert(write2 != NULL);
	sched_start_thread(write2);

	struct thread *read1 = sched_create_thread(rwlock_read, THREAD_KERNEL, NULL);
	assert(read1 != NULL);
	struct thread *read2 = sched_create_thread(rwlock_read, THREAD_KERNEL, NULL);
	assert(read2 != NULL);
	sched_start_thread(read1);
	sched_start_thread(read2);

	rwlock_write((void *) 1);

	while(rw_alive_threads != 0)
		cpu_relax();

	return true;
}

DECLARE_TEST(rwlock_test, 4);

#endif
