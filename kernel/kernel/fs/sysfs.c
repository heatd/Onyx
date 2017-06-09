/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <kernel/panic.h>
#include <kernel/dev.h>
#include <kernel/sysfs.h>
#include <kernel/vfs.h>
#include <kernel/list.h>

/* TODO: Add mkdir support(requires VFS support) */
struct sysfs_file sysfs_root = {0};
struct sysfs_file *lookup_in_sysfs_dirent(struct sysfs_file *file, char *segm)
{
	struct list_head *list = &file->children;
	if(!list)
		return NULL;
	while(list && list->ptr)
	{
		struct sysfs_file *f = list->ptr;
		if(!strcmp(f->name, segm))
			return f;
		list = list->next;
	}
	return NULL;
}
struct sysfs_file *sysfs_create_file(char *name, char *abs)
{
	struct sysfs_file *file = malloc(sizeof(struct sysfs_file));
	if(!file)
	{
		errno = ENOMEM;
		goto error;
	}
	file->children.ptr = NULL;
	file->children.next = NULL;
	file->name = strdup(name);
	if(!file->name)
	{
		errno = ENOMEM;
		goto error;
	}
	file->vnode = malloc(sizeof(vfsnode_t));
	if(!file->vnode)
	{
		errno = ENOMEM;
		goto error;
	}
	file->vnode->name = strdup(abs);
	if(!file->vnode->name)
	{
		errno = ENOMEM;
		goto error;
	}
	file->vnode->inode = (ino_t) file;
	return file;
error:
	if(file)	free(file->name);
	if(file)	free(file->vnode->name);
	if(file)	free(file->vnode);
	free(file);
	return NULL;
}
vfsnode_t *sysfs_creat(const char *pathname, int mode, vfsnode_t *node)
{
	char *path = NULL;
	char *segm;
	char *saveptr;
	char *next_segm;
	struct sysfs_file *file;
	struct sysfs_file *f = NULL;

	path = strdup(pathname);
	if(!path) return errno = ENOMEM, NULL;
	segm = strtok_r(path, "/", &saveptr);
	file = (struct sysfs_file*) node->inode;
	if(!file)
	{
		errno = EBADFD;
		goto error;
	}

	while(segm)
	{
		next_segm = strtok_r(NULL, "/", &saveptr);
		if(next_segm)
		{
			file = lookup_in_sysfs_dirent(file, segm);
			if(!file)
				goto error;
		}
		else
			break;	
		segm = next_segm;
	}
	char *absolute = vfs_get_full_path(node, (char*) pathname);
	if(!absolute)
	{
		errno = ENOMEM;
		goto error;
	}
	f = sysfs_create_file(segm, (char*) absolute);
	if(!f)
		goto error;
	f->vnode->dev = file->vnode->dev;
	if(!file->children.ptr)
	{
		file->children.ptr = f;
	}
	else
	{
		if(list_add(&file->children, f) < 0)
			goto error;
	}
	return file->vnode;
error:
	free(path);
	if(f) 		free(f->name);
	if(f->vnode) 	free(f->vnode->name);
	if(f) 		free(f->vnode);
	free(f);
	return NULL;
}
struct sysfs_file *sysfs_create_entry(const char *pathname, int mode, vfsnode_t *node)
{
	char *path = NULL;
	char *segm;
	char *saveptr;
	char *next_segm;
	struct sysfs_file *file;
	struct sysfs_file *f = NULL;

	path = strdup(pathname);
	if(!path) return errno = ENOMEM, NULL;
	segm = strtok_r(path, "/", &saveptr);
	file = (struct sysfs_file*) node->inode;
	if(!file)
	{
		errno = EBADFD;
		goto error;
	}

	while(segm)
	{
		next_segm = strtok_r(NULL, "/", &saveptr);
		if(next_segm)
		{
			file = lookup_in_sysfs_dirent(file, segm);
			if(!file)
				goto error;
		}
		else
			break;	
		segm = next_segm;
	}
	char *absolute = vfs_get_full_path(node, (char*) pathname);
	if(!absolute)
	{
		errno = ENOMEM;
		goto error;
	}
	f = sysfs_create_file(segm, (char*) absolute);
	if(!f)
		goto error;
	f->vnode->dev = file->vnode->dev;
	if(!file->children.ptr)
	{
		file->children.ptr = f;
	}
	else
	{
		if(list_add(&file->children, f) < 0)
			goto error;
	}
	return file;
error:
	free(path);
	if(f) 		free(f->name);
	if(f->vnode) 	free(f->vnode->name);
	if(f) 		free(f->vnode);
	free(f);
	return NULL;
}
vfsnode_t *sysfs_open(vfsnode_t *node, const char *name)
{
	char *segm;
	char *saveptr;
	char *path = strdup(name);
	if(!path)
		return NULL;
	struct sysfs_file *file = (struct sysfs_file*) node->inode;
	if(!file)
		return NULL; /* This should never happen, maybe in corruption? */
	if(!(file->vnode->type & VFS_TYPE_DIR))
		return errno = ENOTDIR, NULL;
	segm = strtok_r(path, "/", &saveptr);
	 
	/* Iterate through the path */
	while(segm)
	{
		file = lookup_in_sysfs_dirent(file, segm);
		if(!file)
		{
			free(path);
			return errno = ENOENT, NULL;
		}
		segm = strtok_r(NULL, "/", &saveptr);
	}
	free(path);
	return file->vnode;
}
size_t sysfs_read(off_t offset, size_t sizeofread, void *buffer, vfsnode_t *this)
{
	struct sysfs_file *file = (struct sysfs_file*) this->inode;
	if(!file)
		return errno = ENOMEM, (size_t) 0; /* This should never happen, maybe in corruption? */
	if(file->read) return file->read(buffer, sizeofread, offset);
	else
		return errno = ENOSYS, (size_t) -1;
}
size_t sysfs_write(off_t offset, size_t sizeofwrite, void *buffer, vfsnode_t *this)
{
	struct sysfs_file *file = (struct sysfs_file*) this->inode;
	if(!file)
		return errno = ENOMEM, (size_t) 0; /* This should never happen, maybe in corruption? */
	if(file->write) return file->write(buffer, sizeofwrite, offset);
	else
		return errno = ENOSYS, (size_t) -1;
}
void sysfs_init(void)
{
	/* If this function fails, just panic. sysfs is crucial */
	vfsnode_t *root = malloc(sizeof(vfsnode_t));
	if(!root)
		panic("sysfs_init: Could not allocate enough memory!\n");
	memset(root, 0, sizeof(vfsnode_t));

	root->name = "/sys";
	root->type = VFS_TYPE_DIR;
	root->inode = (ino_t) &sysfs_root;
	sysfs_root.vnode = root;
	struct minor_device *minor = dev_register(0, 0);
	if(!minor)
		panic("sysfs_init: Could not allocate a device!\n");
	struct file_ops *fops = malloc(sizeof(struct file_ops));
	if(!fops)
		panic("sysfs_init: Could not allocate the file operation table!\n");
	memset(fops, 0, sizeof(struct file_ops));

	/* Setup the file ops table */
	fops->open = sysfs_open;
	fops->creat = sysfs_creat;

	minor->fops = fops;
	root->dev = minor->majorminor;

	if(mount_fs(root, "/sys") < 0)
		panic("sysfs_init: Could not mount /sys\n");
}
