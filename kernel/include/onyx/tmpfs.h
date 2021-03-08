/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_TMPFS_H
#define _KERNEL_TMPFS_H

#include <onyx/mutex.h>
#include <onyx/vfs.h>
#include <onyx/superblock.h>
#include <onyx/list.h>

#include <sys/types.h>

#ifdef __cplusplus

#include <onyx/atomic.hpp>

struct tmpfs_inode : public inode
{
	/* Used to store the symlink, if it is one */
	const char *link;
};

class tmpfs_superblock : public superblock
{
private:
	atomic<ino_t> curr_inode;
public:
	static atomic<dev_t> curr_minor_number;

	dev_t fs_minor;

	list_head_cpp<tmpfs_superblock> fs_list_node;

	tmpfs_superblock() : superblock{}, curr_inode{}, fs_minor{++curr_minor_number}, fs_list_node{this}
	{
		s_block_size = PAGE_SIZE;
	}

	tmpfs_inode *create_inode(mode_t mode, dev_t rdev = 0);
};

#endif

int tmpfs_mount(const char *mountpoint);

#endif
