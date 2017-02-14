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
#include <stdarg.h>
#include <assert.h>

#include <kernel/panic.h>
#include <kernel/vfs.h>
#include <kernel/dev.h>
#include <kernel/log.h>

vfsnode_t *fs_root = NULL;
vfsnode_t *mount_list = NULL;
int vfs_init()
{
	mount_list = malloc(sizeof(vfsnode_t));
	if(!mount_list)
		panic("Error while allocating the mount list!\n");
	memset(mount_list, 0 ,sizeof(vfsnode_t));
	if(!mount_list)
		return 1;
	fs_root = mount_list;
	memset(fs_root, 0 ,sizeof(vfsnode_t));
	return 0;
}
size_t read_vfs(size_t offset, size_t sizeofread, void* buffer, vfsnode_t* this)
{
	struct minor_device *m = dev_find(this->dev);
	if(!m)
		return errno = ENODEV;
	if(!m->fops)
		return errno = ENOSYS;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return read_vfs(offset,sizeofread,buffer,this->link);
	if(m->fops->read != NULL)
		return m->fops->read(offset,sizeofread,buffer,this);
	return errno = ENOSYS;
}
size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, vfsnode_t* this)
{
	struct minor_device *m = dev_find(this->dev);
	if(!m)
		return errno = ENODEV;
	if(!m->fops)
		return errno = ENOSYS;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return write_vfs(offset, sizeofwrite, buffer, this->link);
	if(m->fops->write != NULL)
		return m->fops->write(offset,sizeofwrite,buffer,this);

	return errno = ENOSYS;
}
int ioctl_vfs(int request, va_list args, vfsnode_t *this)
{
	struct minor_device *m = dev_find(this->dev);
	if(!m)
		return errno = ENODEV;
	if(!m->fops)
		return errno = ENOSYS;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return ioctl_vfs(request, args, this->link);
	if(m->fops->ioctl != NULL)
		return m->fops->ioctl(request, args, this);
	return errno = ENOSYS, -1;
}
void close_vfs(vfsnode_t* this)
{
	struct minor_device *m = dev_find(this->dev);
	if(!m)
		return;
	if(!m->fops)
		return;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		close_vfs(this->link);
	if(m->fops->close != NULL)
		m->fops->close(this);
}
vfsnode_t *open_vfs(vfsnode_t* this, const char *name)
{
	vfsnode_t *it = mount_list;
	while(it != NULL)
	{
		if(!strcmp((char*) name, it->name))
		{
			return it;
		}
		it = it->next;
	}
	if(memcmp(name, "/dev", strlen("/dev")) == 0 && slashdev)
	{
		this = slashdev;
	}
	struct minor_device *minor = dev_find(this->dev);
	if(!minor)
		return errno = ENOSYS, NULL;
	if(!minor->fops)
		return errno = ENOSYS, NULL;
	if(this->type & VFS_TYPE_MOUNTPOINT)
	{
		size_t s = strlen(this->link->mountpoint);
		return minor->fops->open(this->link, name + s);
	}
	if(minor->fops->open != NULL)
	{
		const char *file = name + strlen(this->name);
		return minor->fops->open(this, file);
	}
	return errno = ENOSYS, NULL;
}
vfsnode_t *creat_vfs(vfsnode_t *this, const char *path, int mode)
{
	struct minor_device *m = dev_find(this->dev);
	if(!m)
		return errno = ENODEV, NULL;
	if(!m->fops)
		return errno = ENOSYS, NULL;
	if(this->type & VFS_TYPE_MOUNTPOINT)
	{
		return creat_vfs(this, path, mode);
	}
	if(m->fops->creat != NULL)
	{
		return m->fops->creat(path, mode, this);
	}
	return errno = ENOSYS, NULL;
}
int mount_fs(vfsnode_t *fsroot, const char *path)
{
	if(!strcmp((char*)path, "/"))
	{
		fs_root->link = fsroot;
		fs_root->dev = fsroot->dev;
		fs_root->type = VFS_TYPE_MOUNTPOINT | VFS_TYPE_DIR;
		if(!fs_root->name) fs_root->name = malloc(2);
		if(!fs_root->name)
		{
			ERROR("mount_fs", "out of memory\n");
		}
		strcpy(fs_root->name, path);
		fsroot->mountpoint = (char*) path;
	}
	else
	{
		vfsnode_t *node = mount_list;
		while(node->next)
		{
			node = node->next;
		}
		node->next = fsroot;
	}
	return 0;
}
unsigned int getdents_vfs(unsigned int count, struct dirent* dirp, vfsnode_t *this)
{
	struct minor_device *m = dev_find(this->dev);
	if(!m)
		return errno = ENODEV;
	if(!m->fops)
		return errno = ENOSYS;
	if(!(this->type & VFS_TYPE_DIR))
		return errno = ENOTDIR, -1;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return getdents_vfs(count, dirp, this->link);
	if(m->fops->getdents != NULL)
		return m->fops->getdents(count, dirp, this);
	
	return errno = ENOSYS, (unsigned int)-1;

}
