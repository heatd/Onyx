/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>

#include <kernel/irq.h>
#include <kernel/mutex.h>
#include <kernel/task_switching.h>

void mutex_lock(mutex_t *mutex)
{
	while(!__sync_bool_compare_and_swap(mutex, 0, 1))
	{
		sched_yield();
	}
	__sync_synchronize();
}
void mutex_unlock(mutex_t *mutex)
{
	__sync_synchronize();
	*mutex = 0;
}
