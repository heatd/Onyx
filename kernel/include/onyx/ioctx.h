/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _IOCTX_H
#define _IOCTX_H

#include <onyx/vfs.h>
#include <onyx/mutex.h>
#include <sys/types.h>
#include <onyx/file.h>

#define FDS_PER_LONG										(sizeof(unsigned long) * 8)
#define FILE_DESCRIPTOR_GROW_NR								(FDS_PER_LONG)

struct ioctx
{
	/* Current working directory */
	struct spinlock cwd_lock;
	struct file *cwd;
	struct mutex fdlock;
	struct file **file_desc;
	unsigned int file_desc_entries;
	unsigned long *cloexec_fds;
	unsigned long *open_fds;
};

#endif
