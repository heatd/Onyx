/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_MUTEX_H
#define _KERNEL_MUTEX_H

typedef volatile unsigned long mutex_t;

void mutex_lock(mutex_t *);
void mutex_unlock(mutex_t*);

#define MUTEX_INITIALIZER 0

#endif
