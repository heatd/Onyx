/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/ref.h>
#include <onyx/atomic.h>
#include <onyx/scheduler.h>

void ref_init(struct ref *ref, unsigned long refcount, void (*releasefunc)(struct ref *))
{
	ref->refcount = refcount;
	ref->release = releasefunc;
}

bool ref_grab(struct ref *ref)
{
	acquire_spinlock(&ref->lock);

	if(ref->refcount == 0)
		return false;

	atomic_inc(&ref->refcount, 1);

	release_spinlock(&ref->lock);

	return true;
}

void ref_release(struct ref *ref)
{
	acquire_spinlock(&ref->lock);

	if(atomic_dec(&ref->refcount, 1) == 0)
	{
		sched_change_preemption_state(ref->lock.old_preemption_state);
		if(ref->release)
			ref->release(ref);
		/* Don't unlock here - the lock may not even exist anymore */
		return;
	}

	release_spinlock(&ref->lock);
}