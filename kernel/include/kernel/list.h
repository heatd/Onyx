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
#ifndef _KERNEL_LIST_H
#define _KERNEL_LIST_H

#include <kernel/compiler.h>

struct list_head
{
	void *ptr __align_cache;
	struct list_head *next __align_cache;
};

#endif