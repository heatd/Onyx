/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/object.h>
#include <onyx/utils.h>

void __object_release(struct ref *ref)
{
	struct object *obj = container_of(ref, struct object, ref);

	if(obj->release) obj->release(obj);
}

void object_init(struct object *object, void (*releasefunc)(struct object *))
{
	object->release = releasefunc;
	ref_init(&object->ref, 1, __object_release);
}

void object_acquire(struct object *source, struct object *target);
void object_release(struct object *source, struct object *target);

bool object_ref(struct object *object)
{
	return ref_grab(&object->ref);
}

void object_unref(struct object *object)
{
	ref_release(&object->ref);
}