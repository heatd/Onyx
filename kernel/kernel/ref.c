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
	atomic_inc(&ref->refcount, 1);

	return true;
}

void ref_release(struct ref *ref)
{
	if(atomic_dec(&ref->refcount, 1) == 0)
	{
		if(ref->release)
			ref->release(ref);
	}
}