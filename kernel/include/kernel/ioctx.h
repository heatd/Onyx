/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _IOCTX_H
#define _IOCTX_H

#include <kernel/vfs.h>
#include <sys/types.h>
#include <limits.h>
typedef struct
{
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
