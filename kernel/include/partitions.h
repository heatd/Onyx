/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PARTITIONS_H
#define _PARTITIONS_H

#include <stdint.h>

#include <sys/types.h>

#include <onyx/block.h>
#include <onyx/vfs.h>

typedef struct inode *(*fs_handler)(struct blockdev *dev);
enum partition_type_t
{
	PARTITION_TYPE_MBR,
	PARTITION_TYPE_GPT
};
typedef struct fs_mount_strct
{
	struct fs_mount_strct *next;
	const char *filesystem;
	fs_handler handler;
} filesystem_mount_t;

int partition_add_handler(fs_handler handler, const char *filesystem);
filesystem_mount_t *find_filesystem_handler(const char *fsname);
struct blockdev;
void partition_setup_disk(struct blockdev *dev);

#endif
