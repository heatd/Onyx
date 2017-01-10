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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include <kernel/vfs.h>
#include <kernel/dev.h>
#include <kernel/compiler.h>
#include <kernel/panic.h>

vfsnode_t *slashdev = NULL;
vfsnode_t **children = NULL;
size_t num_child = 0;

unsigned int devfs_getdents(unsigned int count, struct dirent* dirp, vfsnode_t* this)
{
	unsigned int found = 0;
	for(size_t i = 0; i < num_child; i++)
	{
		strcpy(dirp[found].d_name, "/dev/");
		strcat((char*) &dirp[found].d_name, children[i]->name);
		dirp[found].d_ino = i;
		if(children[i]->type & VFS_TYPE_DIR) dirp[found].d_type = DT_DIR;
		else if(children[i]->type & VFS_TYPE_FILE) dirp[found].d_type = DT_REG;
		else if(children[i]->type & VFS_TYPE_CHAR_DEVICE) dirp[found].d_type = DT_CHR;
		else if(children[i]->type & VFS_TYPE_BLOCK_DEVICE) dirp[found].d_type = DT_BLK;
		else dirp[found].d_type = DT_UNKNOWN;
		if(++found == count)
			break;
	}
	return found;
}
vfsnode_t *devfs_open(vfsnode_t *this, const char *name)
{
	if(!children)
		return errno = ENOENT, NULL;
	for(size_t i = 0; i < num_child; i++)
	{
		if(strcmp((char*) name, (char*) children[i]->name) == 0)
		{
			return children[i];
		}
	}
	return errno = ENOENT, NULL;
}
vfsnode_t *devfs_creat(const char *pathname, int mode, vfsnode_t *self)
{
	(void) self;
	pathname += strlen("/dev/");
	if(!children)
	{
		num_child++;
		children = malloc(sizeof(void*) * num_child);
		children[0] = malloc(sizeof(vfsnode_t));
		memset(children[0], 0, sizeof(vfsnode_t));
		children[0]->name = (char*) pathname;
		children[0]->inode = 0;
		children[0]->type = VFS_TYPE_FILE;
		return children[0];
	}
	else
	{
		num_child++;
		children = realloc(children, sizeof(void*) * num_child);
		children[num_child-1] = malloc(sizeof(vfsnode_t));
		memset(children[num_child-1], 0, sizeof(vfsnode_t));
		children[num_child-1]->name = (char*) pathname;
		children[num_child-1]->inode = num_child-1;
		children[num_child-1]->type = VFS_TYPE_FILE;
		return children[num_child-1];
	}
}
int devfs_init()
{
	vfsnode_t *i = open_vfs(fs_root, "/dev/");
	if(unlikely(!i))
		panic("/dev not found!");

	slashdev = malloc(sizeof(vfsnode_t));
	if(!slashdev)
		panic("Out-of-memory while creating /dev!");
	memset(slashdev, 0, sizeof(vfsnode_t));
	i->link = slashdev;
	i->type |= VFS_TYPE_MOUNTPOINT;
	slashdev->name = "/dev/";
	slashdev->type = VFS_TYPE_DIR;
	slashdev->open = devfs_open;
	slashdev->getdents = devfs_getdents;
	slashdev->creat = devfs_creat;
	return 0;
}
