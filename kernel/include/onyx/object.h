/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_OBJECT_H
#define _ONYX_OBJECT_H

#include <onyx/ref.h>

struct ref;

struct object
{
    const char *name;
    unsigned long flags;
    struct ref ref;

    /* Each object stores acquired objects in here. */
    /* This helps keeping track of reference counts */
    struct object *acquired_objects;

    void (*release)(struct object *object);
};

void object_init(struct object *object, void (*releasefunc)(struct object *));
void object_acquire(struct object *source, struct object *target);
void object_release(struct object *source, struct object *target);
bool object_ref(struct object *object);
void object_unref(struct object *object);

#endif
