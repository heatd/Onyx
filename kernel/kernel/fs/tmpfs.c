/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <string.h>

#include <kernel/tmpfs.h>
#include <kernel/log.h>
#include <kernel/vfs.h>

tmpfs_filesystem_t *filesystems = NULL;

int __tmpfs_allocate_fs()
{
	tmpfs_filesystem_t *fs = filesystems;

	int num = 0;
	tmpfs_filesystem_t *last_fs = fs;
	while(fs)
	{
		last_fs = fs;
		fs = fs->next;
		num++;
	}

	tmpfs_filesystem_t *new_fs = malloc(sizeof(tmpfs_filesystem_t));
	if(!new_fs)
		return -1;
	memset(new_fs, 0, sizeof(tmpfs_filesystem_t));

	tmpfs_file_t *new_root = malloc(sizeof(tmpfs_file_t));
	if(!new_root)
		return -1;
	memset(new_root, 0, sizeof(tmpfs_file_t));
	
	/* Setup the tmpfs root */
	new_root->name = "";
	new_root->parent = new_root;
	
	new_fs->root = new_root;
	if(last_fs) last_fs->next = new_fs;
	else filesystems = new_fs;

	return num;
}
int tmpfs_mount(const char *mountpoint)
{
	LOG("tmpfs", "Mounting on %s\n", mountpoint);

	int fs_num = __tmpfs_allocate_fs();

	vfsnode_t *node = malloc(sizeof(vfsnode_t));
	if(!node)
		return -1;
	memset(node, 0, sizeof(vfsnode_t));

	node->name = "";
	node->mountpoint = (char*) mountpoint;
	node->type = VFS_TYPE_DIR | VFS_TYPE_MOUNTPOINT;
	node->dev = fs_num;

	return 0;
}