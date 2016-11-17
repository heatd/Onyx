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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#include <kernel/panic.h>
#include <kernel/vfs.h>

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
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return this->link->write(offset,sizeofwrite,buffer,this->link);
	if(this->write != NULL)
		return this->write(offset,sizeofwrite,buffer,this);

	return errno = ENOSYS;
}
int ioctl_vfs(int request, va_list args, vfsnode_t *this)
{
	if(this->ioctl != NULL)
		return this->ioctl(request, args, this);
	return errno = ENOSYS, -1;
}
void close_vfs(vfsnode_t* this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		this->link->close(this->link);
	if(this->close != NULL)
		this->close(this);
}
vfsnode_t *open_vfs(vfsnode_t* this, const char *name)
{
	vfsnode_t *it = mount_list;
	while(it != NULL)
	{
		if(strcmp(name, it->name) == 0)
		{
			return it;
		}
		it = it->next;
	}
	if(this->type & VFS_TYPE_MOUNTPOINT)
	{
		size_t s = strlen(this->link->mountpoint);
		return this->link->open(this->link, name + s);
	}
	if(this->open != NULL)
	{
		const char *file = name + strlen(this->name);
		return this->open(this, file);
	}
	return errno = ENOSYS, NULL;
}
int mount_fs(vfsnode_t *fsroot, const char *path)
{
	printf("Mountfs\n");
	if(!strcmp((char*)path, "/"))
	{
		printf("Mounting root\n");
		fs_root->link = fsroot;
		fs_root->type = VFS_TYPE_MOUNTPOINT | VFS_TYPE_DIR;
		if(!fs_root->name) fs_root->name = malloc(2);
		assert(fs_root->name);
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
		node->type = VFS_TYPE_MOUNTPOINT | VFS_TYPE_DIR;
		node->name = malloc(strlen(path) + 1);
		strcpy(node->name, path);
		fsroot->mountpoint = (char*)path;
	}
	return 0;
}
unsigned int getdents_vfs(unsigned int count, struct dirent* dirp, vfsnode_t *this)
{
	if(!(this->type & VFS_TYPE_DIR))
		return errno = ENOTDIR, -1;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return this->link->getdents(count, dirp, this->link);
	if(this->getdents != NULL)
		return this->getdents(count, dirp, this);
	
	return errno = ENOSYS, (unsigned int)-1;

}