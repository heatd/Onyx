/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _IOCTX_H
#define _IOCTX_H

#include <kernel/vfs.h>
#include <sys/types.h>
#include <limits.h>
typedef struct
{
	int refcount;
	off_t seek;
	vfsnode_t *vfs_node;
	int flags;
} file_desc_t;
typedef struct
{
	const char *working_dir;
	file_desc_t *file_desc[UINT8_MAX];
} ioctx_t;

#endif
