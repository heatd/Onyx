/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_REF_H
#define _ONYX_REF_H
#include <stdbool.h>

#include <onyx/spinlock.h>

struct ref
{
	unsigned long refcount;
	void (*release)(struct ref *ref);
};

void ref_init(struct ref *ref, unsigned long refcount, void (*releasefunc)(struct ref *));
bool ref_grab(struct ref *ref);
void ref_release(struct ref *ref);

#endif