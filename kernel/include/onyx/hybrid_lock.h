/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_HYBRID_LOCK_H
#define _ONYX_HYBRID_LOCK_H

#include <onyx/wait_queue.h>
#include <onyx/spinlock.h>
#include <onyx/conditional.h>
#include <onyx/scoped_lock.h>

/**
 * @brief Works in a similar fashion to linux's socket_lock_t.
 * When used in a user context, the lock's user is supposed to lock it like a mutex, which may block.
 * When used in a bottom-half-like context, the user is supposed to take the lock, and check if it
 * actually owns it.
 * 
 */
class hybrid_lock
{
private:
	struct spinlock lock;
	raw_spinlock_t owned;
	wait_queue wq;

	void __wait_for_owned()
	{
		wait_for_event_locked(&wq, owned != 0, &lock);
	}

public:

	hybrid_lock() : owned{}, wq{}
	{
		init_wait_queue_head(&wq);
		spinlock_init(&lock);
	}

	void lock()
	{
		scoped_lock g{lock};

		if(owned)
			__wait_for_owned();
		owned = get_cpu_nr() + 1;
	}

	void unlock()
	{
		scoped_lock g{lock};

		owned = 0;
	}

	void lock_bh()
	{
		spin_lock(&lock);
	}

	void unlock_bh()
	{
		spin_unlock(&lock);
	}
};

#endif
