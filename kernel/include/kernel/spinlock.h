/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _SPINLOCK_H
#define _SPINLOCK_H

typedef struct spinlock
{
	unsigned long lock;
}spinlock_t;

extern void acquire_spinlock(spinlock_t*);
extern void release_spinlock(spinlock_t*);
void wait_spinlock(spinlock_t*);
#endif
