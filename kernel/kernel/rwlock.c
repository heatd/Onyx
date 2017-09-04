/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <onyx/rwlock.h>
/* TODO: Implement this properly*/
void rw_lock_read(struct rwlock *lock)
{
	if(lock->rw == 0) /* is reading, just return */
	{
		lock->readers++;
		return;
	}
	//while(!__sync_bool_compare_and_swap(lock->lock, 0, 1))
}
