/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <kernel/rwlock.h>
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