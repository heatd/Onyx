/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <kernel/vfs.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <kernel/panic.h>
vfsnode_t *fs_root = NULL;
vfsnode_t *mount_list = NULL;
int vfs_init()
{
	mount_list = malloc(sizeof(vfsnode_t));
	memset(mount_list, 0 ,sizeof(vfsnode_t));
	if(!mount_list)
		return 1;
	fs_root = mount_list;
	memset(fs_root, 0 ,sizeof(vfsnode_t));
	return 0;
}
size_t read_vfs(size_t offset, size_t sizeofread, void* buffer, vfsnode_t* this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return this->link->read(offset,sizeofread,buffer,this->link);
	if(this->read != NULL)
		return this->read(offset,sizeofread,buffer,this);
	return errno = ENOSYS;
}
size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, vfsnode_t* this)
{
	if(this->write != NULL)
		return this->write(offset,sizeofwrite,buffer,this);
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return this->link->write(offset,sizeofwrite,buffer,this->link);

	return errno = ENOSYS;
}
void close_vfs(vfsnode_t* this)
{
	if(this->close != NULL)
		this->close(this);
	if(this->type & VFS_TYPE_MOUNTPOINT)
		this->link->close(this->link);
}
vfsnode_t *open_vfs(vfsnode_t* this, const char *name)
{
	if(this->open != NULL)
	{
		const char *file = name + strlen(this->name);
		return this->open(this, file);
	}
	if(this->type & VFS_TYPE_MOUNTPOINT)
	{
		size_t s = strlen(this->link->mountpoint);
		return this->link->open(this->link, name + s);
	}

	return errno = ENOSYS, NULL;
}
int mount_fs(vfsnode_t *fsroot, const char *path)
{
	if(!strcmp((char*)path, "/"))
	{
		fs_root->link = fsroot;
		fs_root->type |= VFS_TYPE_MOUNTPOINT;
		if(!fs_root->name)
			fs_root->name = malloc(2);
		if(!fs_root->name)
			panic("OOM while allocating fs_root->name");
		strcpy(fs_root->name, path);
		fsroot->mountpoint = (char*)path;
	}
	else
	{
		vfsnode_t *node = mount_list;
		while(node->name)
		{
			node = node->next;
		}
		node->link = fsroot;
		node->type |= VFS_TYPE_MOUNTPOINT;
		node->name = malloc(strlen(path));
		strcpy(node->name, path);
		fsroot->mountpoint = (char*)path;
	}
	return 0;
}
struct dirent *readdir_fs(vfsnode_t* this, unsigned int index)
{
	if(this->type != VFS_TYPE_DIR)
		return errno = ENOTDIR, NULL;
	const char* base_path = this->name;
	size_t len = strlen(base_path);
	unsigned int index_count = 0;
	vfsnode_t* search = mount_list;
	for ((void) search; search != NULL; search = search->next) {
		if (memcmp(search->name, base_path, len) == 0)
		{
			if(index_count == index)
				printf("search->name: %s\n", search->name);
			index_count++;
		}
	}
	return NULL;
}
