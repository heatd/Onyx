/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PIPE_H
#define _KERNEL_PIPE_H

#include <kernel/mutex.h>
#include <kernel/vfs.h>

struct pipe
{
	struct pipe *next;
	void *buffer;
	size_t buf_size;
	size_t curr_size;
	int readers;
	mutex_t pipe_lock;
};
struct inode *pipe_create(void);



#endif
