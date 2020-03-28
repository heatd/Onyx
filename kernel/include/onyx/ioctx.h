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

struct ioctx
{
	/* Current working directory */
	struct file *cwd;
	const char *name;
	struct mutex fdlock;
	struct file **file_desc;
	int file_desc_entries;
};

struct file *create_file_description(struct inode *inode, off_t seek);

#endif
