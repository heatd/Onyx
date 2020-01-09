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
#include <limits.h>

struct file
{
#ifndef __cplusplus
	_Atomic
#endif	
	unsigned long refcount;
	off_t seek;
	struct inode *vfs_node;
	int flags;
};

typedef struct
{
	/* Current working directory */
	struct file *cwd;
	const char *name;
	struct mutex fdlock;
	struct file **file_desc;
	int file_desc_entries;
} ioctx_t;

struct file *create_file_description(struct inode *inode, off_t seek);
void close_file_description(struct file *fd);

#endif
