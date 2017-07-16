/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>

#include <kernel/list.h>
#include <kernel/futex.h>
#include <kernel/process.h>

struct futex *__get_futex(int *uaddr)
{
	for(struct futex *f = get_current_process()->futex_queue; f; f = f->next)
	{
		if(f->address == uaddr)
			return f;
	}
	return NULL;
}
void __futex_insert(struct futex *futex)
{
	process_t *current = get_current_process();
	acquire_spinlock(&current->futex_queue_lock);
	if(!current->futex_queue)
		current->futex_queue = futex;
	else
	{
		struct futex *f = current->futex_queue;
		while(f->next) f = f->next;
		f->next = futex;
	}
	release_spinlock(&current->futex_queue_lock);
}
struct futex *futex_insert(int *uaddr)
{
	struct futex *futex = malloc(sizeof(struct futex));
	if(!futex)
		return NULL;
	memset(futex, 0, sizeof(struct futex));
	futex->address = uaddr;
	__futex_insert(futex);
	return futex;
}
struct futex *get_futex(int *uaddr)
{
	struct futex *futex = __get_futex(uaddr);
	if(!futex)
		futex = futex_insert(uaddr);
	return futex;
}
int futex_enqueue_thread(struct futex *ftx)
{
	acquire_spinlock(&ftx->block_thread_lock);
	if(!ftx->waiting_threads)
	{
		ftx->waiting_threads = malloc(sizeof(struct list_head));
		if(!ftx->waiting_threads)
		{
			release_spinlock(&ftx->block_thread_lock);
			return -1;
		}
		ftx->waiting_threads->ptr = get_current_thread();
		ftx->waiting_threads->next = NULL;
	}
	else
	{
		if(list_add(ftx->waiting_threads, get_current_thread()) < 0)
		{
			release_spinlock(&ftx->block_thread_lock);
			return -1;
		}
	}
	release_spinlock(&ftx->block_thread_lock);
	return 0;
}
void futex_sleep_until_wake(const struct timespec *timeout)
{
	unsigned long waiting_time = 0;
	if(vmm_check_pointer((void*) timeout, sizeof(struct timespec)) > 0)
	{
		waiting_time = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
	}
	if(waiting_time)
		sched_sleep(waiting_time);
	else
		sched_sleep_until_wake();
}
int futex_wait(int *uaddr, int val, struct futex *ftx, const struct timespec *timeout)
{
	if(__sync_bool_compare_and_swap(uaddr, val, val) == true)
	{
		/* If *uaddr != val, enqueue the thread, and sleep until woken up by FUTEX_WAKE */
		if(futex_enqueue_thread(ftx) < 0)
			return -ENOMEM;
		futex_sleep_until_wake(timeout);
		if(get_current_thread()->woken_up_by_futex == false)
			return -ETIMEDOUT;
	}
	else
		return -EAGAIN;
	return 0;
}
int futex_wake(struct futex *ftx, int val)
{
	int woken_up = 0;
	acquire_spinlock(&ftx->block_thread_lock);
	struct list_head *thr_list = ftx->waiting_threads;
	while(val-- && thr_list)
	{
		thread_wake_up_ftx(thr_list->ptr);
		struct list_head *l = thr_list;
		thr_list = thr_list->next;
		free(l);
		woken_up++;
	}
	ftx->waiting_threads = thr_list;
	release_spinlock(&ftx->block_thread_lock);
	return woken_up;
}
int sys_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3)
{
	if(vmm_check_pointer(uaddr, sizeof(int)) < 0)
		return -EFAULT;
	/* The pointer needs to be 4-byte aligned */
	if((uintptr_t) uaddr & 0xF)
		return -EINVAL;
	struct futex *futex = get_futex(uaddr);	
	if(!futex)
		return -ENOMEM;
	switch(futex_op & FUTEX_OP_MASK)
	{
		case FUTEX_WAIT:
			return futex_wait(uaddr, val, futex, timeout);
		case FUTEX_WAKE:
			return futex_wake(futex, val);
		default:
			return -ENOSYS;
	}
}
