/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_TMPFS_H
#define _KERNEL_TMPFS_H

typedef struct data_blk
{
	struct data_blk *next;
	char data[0];
} tmpfs_data_block_t;

typedef struct tmpfs_file
{
	const char *name;
	tmpfs_data_block_t *data;
	struct tmpfs_file *sibblings;
	struct tmpfs_file *parent;
	struct tmpfs_file *child;
} tmpfs_file_t;

typedef struct tmpfs_filesystem
{
	struct tmpfs_filesystem *next;
	tmpfs_file_t *root;
} tmpfs_filesystem_t;
#endif