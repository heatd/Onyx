/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_PIPE_H
#define _KERNEL_PIPE_H

#include <kernel/vfs.h>

struct pipe
{
	struct pipe *next;
	void *buffer;
	size_t buf_size;
	size_t curr_size;
};
vfsnode_t *pipe_create(void);



#endif