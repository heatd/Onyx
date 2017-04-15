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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#include <kernel/avl.h>
#include <kernel/panic.h>
#include <kernel/vfs.h>
#include <kernel/dev.h>
#include <kernel/pagecache.h>
#include <kernel/log.h>

static avl_node_t **avl_search_key(avl_node_t **t, uintptr_t key);
vfsnode_t *fs_root = NULL;
vfsnode_t *mount_list = NULL;
ssize_t do_file_caching(size_t sizeofread, vfsnode_t *this, struct minor_device *m, off_t offset)
{
	if(this->type != VFS_TYPE_FILE) /* Only VFS_TYPE_FILE files can be cached */
		return -1;
	void *cache = malloc(PAGE_CACHE_SIZE);
	if(!cache)
		return -1;
	memset(cache, 0, PAGE_CACHE_SIZE);
	ssize_t read = 0;
	size_t max_reads = sizeofread % PAGE_CACHE_SIZE ? (sizeofread / PAGE_CACHE_SIZE) + 1 : sizeofread / PAGE_CACHE_SIZE;
	size_t toread = offset + sizeofread > this->size ? sizeofread - offset - sizeofread + this->size : sizeofread;
	sizeofread = toread;
	for(size_t i = 0; i < max_reads; i++)
	{
		if(avl_search_key(&this->cache_tree, offset + PAGE_CACHE_SIZE * i))
			continue;
		size_t status = m->fops->read(offset + PAGE_CACHE_SIZE * i, PAGE_CACHE_SIZE, cache, this);
		if(status == 0)
		{
			free(cache);
			return read;
		}
		if(!add_cache_to_node(cache, offset + PAGE_CACHE_SIZE * i, this))
		{
			free(cache);
			return read;
		}
		toread -= PAGE_CACHE_SIZE;
		read += status;
		memset(cache, 0, PAGE_CACHE_SIZE);
	}
	free(cache);
	return sizeofread;
}
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
		return read_vfs(offset, sizeofread, buffer, this->link);
	if(m->fops->read != NULL)
	{
		ssize_t status; 
		if((status = lookup_file_cache(buffer, sizeofread, this, m, offset)) < 0) /* If caching failed, just do the normal way */
			return m->fops->read(offset, sizeofread, buffer, this);
		return status;
	}
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
unsigned int getdents_vfs(unsigned int count, struct dirent* dirp, off_t off, vfsnode_t *this)
{
	struct minor_device *m = dev_find(this->dev);
	if(!m)
		return errno = ENODEV;
	if(!m->fops)
		return errno = ENOSYS;
	if(!(this->type & VFS_TYPE_DIR))
		return errno = ENOTDIR, -1;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return getdents_vfs(count, dirp, off, this->link);
	if(m->fops->getdents != NULL)
		return m->fops->getdents(count, dirp, off, this);
	
	return errno = ENOSYS, (unsigned int) -1;
}
int stat_vfs(struct stat *buf, vfsnode_t *node)
{
	struct minor_device *m = dev_find(node->dev);
	if(!m)
		return errno = ENODEV;
	if(!m->fops)
		return errno = ENOSYS;
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return stat_vfs(buf, node->link);
	if(m->fops->stat != NULL)
		return m->fops->stat(buf, node);
	
	return errno = ENOSYS, (unsigned int) -1;
}
typedef struct avl_node
{
	struct avl_node *left, *right;
	uintptr_t key; /* In this case, key == offset */
	void *ptr;
} avl_node_t;
static avl_node_t *avl_insert_key(avl_node_t **t, uintptr_t key, vfsnode_t *vfs)
{
	avl_node_t *ptr = *t;
	if(!*t)
	{
		*t = malloc(sizeof(avl_node_t));
		if(!*t)
			return NULL;
		memset(*t, 0, sizeof(avl_node_t));
		ptr = *t;
		ptr->key = key;
		return ptr;
	}
	else if (key < ptr->key)
	{
		avl_node_t *ret = avl_insert_key(&ptr->left, key, vfs);
		avl_balance_tree(&vfs->cache_tree);
		return ret;
	}
	else if(key == ptr->key)
	{
		return NULL;
	}
	else
	{
		avl_node_t *ret = avl_insert_key(&ptr->right, key, vfs);
		avl_balance_tree(&vfs->cache_tree);
		return ret;
	}
}
static avl_node_t **avl_search_key(avl_node_t **t, uintptr_t key)
{
	if(!*t)
		return NULL;
	avl_node_t *ptr = *t;
	if(key == ptr->key)
		return t;
	if(key > ptr->key && key < ptr->key + 64 * 1024)
		return t;
	if(key < ptr->key)
		return avl_search_key(&ptr->left, key);
	else
		return avl_search_key(&ptr->right, key);
}
static int avl_delete_node(uintptr_t key, avl_node_t **tree)
{
	/* Try to find the node inside the tree */
	avl_node_t **n = avl_search_key(tree, key);
	if(!n)
		return errno = ENOENT, -1;
	avl_node_t *ptr = *n;

	/* Free up all used memory and set *n to NULL */
	vfree(ptr->ptr, 64 * 1024);
	free(ptr);
	*n = NULL;
	avl_balance_tree(tree);
	return 0;
}
void *add_cache_to_node(void *ptr, off_t offset, vfsnode_t *node)
{
	void *cache = add_to_cache(ptr, node);
	if(!cache)
		return NULL;
	avl_node_t *avl = avl_insert_key(&node->cache_tree, (uintptr_t) offset, node);
	if(!avl)
		return NULL;
	avl->ptr = cache;

	return avl->ptr;
}
ssize_t lookup_file_cache(void *buffer, size_t sizeofread, vfsnode_t *file, struct minor_device *m, off_t offset)
{
	if(file->type != VFS_TYPE_FILE)
		return -1;
	if((size_t) offset > file->size)
		return 0;
	if(offset != 0)
		printk("OFFSET %u\n", offset);
	do_file_caching(sizeofread, file, m, offset & PAGE_CACHE_SIZE);
	size_t read = 0;
	while(read != sizeofread)
	{
		avl_node_t **tree_node = NULL;
		if(!(tree_node = avl_search_key(&file->cache_tree, offset)))
			return read;
		avl_node_t *nd = *tree_node;
		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;
		if(rest < 0) rest = 0;
		size_t amount = sizeofread - read < (size_t) rest ? sizeofread - read : (size_t) rest;
		memcpy((char*) buffer + read, (char*) nd->ptr + cache_off, amount);
		offset += amount;
		read += amount;
	}
	return (ssize_t) read;
}