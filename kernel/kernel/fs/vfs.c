/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <libgen.h>

#include <kernel/avl.h>
#include <kernel/panic.h>
#include <kernel/vfs.h>
#include <kernel/dev.h>
#include <kernel/pagecache.h>
#include <kernel/log.h>
#include <kernel/mtable.h>

static avl_node_t **avl_search_key(avl_node_t **t, uintptr_t key);
vfsnode_t *fs_root = NULL;
vfsnode_t *mount_list = NULL;
ssize_t write_file_cache(void *buffer, size_t sizeofwrite, vfsnode_t *file, off_t offset);

#define FILE_CACHING_WRITE	1
ssize_t do_file_caching(size_t sizeofread, vfsnode_t *this, off_t offset, int flags)
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
		size_t status = this->fops.read(0, offset + PAGE_CACHE_SIZE * i, PAGE_CACHE_SIZE, cache, this);

		if(status == 0 && !(flags & FILE_CACHING_WRITE))
		{
			free(cache);
			return read;
		}
		if(!add_cache_to_node(cache, status, offset + PAGE_CACHE_SIZE * i, this))
		{
			free(cache);
			return read;
		}
		toread -= status;
		read += status;
		memset(cache, 0, PAGE_CACHE_SIZE);
	}
	free(cache);
	return read;
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
	fs_root->refcount++;
	return 0;
}
size_t read_vfs(int flags, size_t offset, size_t sizeofread, void* buffer, vfsnode_t* this)
{
	if(this->type & VFS_TYPE_DIR)
		return errno = EISDIR, -1;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return read_vfs(flags, offset, sizeofread, buffer, this->link);
	if(this->fops.read != NULL)
	{
		ssize_t status; 
		if((status = lookup_file_cache(buffer, sizeofread, this, offset)) < 0) /* If caching failed, just do the normal way */
			return this->fops.read(flags, offset, sizeofread, buffer, this);
		return status;
	}
	return errno = ENOSYS;
}
size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, vfsnode_t* this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return write_vfs(offset, sizeofwrite, buffer, this->link);
	if(this->fops.write != NULL)
	{
		ssize_t status; 
		if((status = write_file_cache(buffer, sizeofwrite, this, offset)) < 0) /* If caching failed, just do the normal way */
			return this->fops.write(offset, sizeofwrite, buffer, this);
		if(offset + sizeofwrite > this->size)
		{
			this->size = offset + sizeofwrite;
		}
		return status;
	}

	return errno = ENOSYS;
}
int ioctl_vfs(int request, char *argp, vfsnode_t *this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return ioctl_vfs(request, argp, this->link);
	if(this->fops.ioctl != NULL)
		return this->fops.ioctl(request, (void*) argp, this);
	return errno = ENOSYS, -1;
}
void close_vfs(vfsnode_t* this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		close_vfs(this->link);
	if(this->fops.close != NULL)
		this->fops.close(this);
	__sync_fetch_and_sub(&this->refcount, 1);
	if(this->refcount == 0)
	{
		free(this);
	}
}
vfsnode_t *do_actual_open(vfsnode_t *this, const char *name)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
	{
		return do_actual_open(this->link, name);
	}
	if(this->fops.open != NULL)
	{
		return this->fops.open(this, name);
	}
	return errno = ENOSYS, NULL;
}
vfsnode_t *open_path_segment(char *segm, vfsnode_t *node)
{
	vfsnode_t *file = do_actual_open(node, segm);
	if(!file)
		return NULL;	
	vfsnode_t *mountpoint = NULL;
	if((mountpoint = mtable_lookup(file)))
		file = mountpoint;
	return file;
}
vfsnode_t *open_vfs(vfsnode_t* this, const char *name)
{
	/* Okay, so we need to traverse the path */
	/* First off, dupe the string */
	char *path = strdup(name);
	if(!path)
		return errno = ENOMEM, NULL;
	char *saveptr;
	char *orig = path;
	/* Now, tokenize it using strtok */
	path = strtok_r(path, "/", &saveptr);
	vfsnode_t *node = this;
	while(path)
	{
		node = open_path_segment(path, node);
		if(!node)
		{
			free(orig);
			return NULL;
		}
		path = strtok_r(NULL, "/", &saveptr);
	}
	free(orig);
	return node;
}
vfsnode_t *creat_vfs(vfsnode_t *this, const char *path, int mode)
{
	char *dup = strdup(path);
	if(!dup)
		return errno = ENOMEM, NULL;
	char *dir = dirname((char*) dup);
	vfsnode_t *base;
	if(*dir != '.' && strlen(dir) != 1)
		base = open_vfs(this, dir);
	else
		base = this;
	
	/* Reset the string again */
	strcpy(dup, path);
	if(!base)
	{
		errno = ENOENT;
		goto error;
	}
	if(base->type & VFS_TYPE_MOUNTPOINT)
	{
		vfsnode_t *node = creat_vfs(base, basename((char*) dup), mode);
		free(dup);
		return node;
	}
	if(this->fops.creat != NULL)
	{
		vfsnode_t *ret = this->fops.creat(basename((char*) dup), mode, base);
		free(dup);
		return ret;
	}
	errno = ENOSYS;
error:
	free(dup);
	return NULL;
}
int mount_fs(vfsnode_t *fsroot, const char *path)
{
	printf("mount_fs: Mounting on %s\n", path);
	if(!strcmp((char*)path, "/"))
	{
		fs_root->link = fsroot;
		fs_root->dev = fsroot->dev;
		fs_root->type = VFS_TYPE_MOUNTPOINT | VFS_TYPE_DIR;
		if(!fs_root->name) fs_root->name = malloc(2);
		if(!fs_root->name)
		{
			ERROR("mount_fs", "out of memory\n");
			while(1);
		}
		strcpy(fs_root->name, path);
		fsroot->mountpoint = (char*) path;
	}
	else
	{
		vfsnode_t *file = open_vfs(fs_root, dirname((char*) path));
		if(!file)
			return -ENOENT;
		file = do_actual_open(file, basename((char*) path));
		if(!file)
			return -ENOENT;
		return mtable_mount(file, fsroot);
	}
	return 0;
}
unsigned int getdents_vfs(unsigned int count, struct dirent* dirp, off_t off, vfsnode_t *this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return getdents_vfs(count, dirp, off, this->link);
	if(!(this->type & VFS_TYPE_DIR))
		return errno = ENOTDIR, -1;
	if(this->fops.getdents != NULL)
		return this->fops.getdents(count, dirp, off, this);
	
	return errno = ENOSYS, (unsigned int) -1;
}
int stat_vfs(struct stat *buf, vfsnode_t *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return stat_vfs(buf, node->link);
	if(node->fops.stat != NULL)
		return node->fops.stat(buf, node);
	
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
void *add_cache_to_node(void *ptr, size_t size, off_t offset, vfsnode_t *node)
{
	struct page_cache *cache = add_to_cache(ptr, size, offset, node);
	if(!cache)
		return NULL;
	avl_node_t *avl = avl_insert_key(&node->cache_tree, (uintptr_t) offset, node);
	if(!avl)
		return NULL;
	avl->ptr = cache;

	return avl->ptr;
}
ssize_t lookup_file_cache(void *buffer, size_t sizeofread, vfsnode_t *file, off_t offset)
{
	if(file->type != VFS_TYPE_FILE)
		return -1;
	if((size_t) offset > file->size)
		return 0;
	off_t off = (offset / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;
	do_file_caching(sizeofread, file, off, 0);
	size_t read = 0;
	while(read != sizeofread)
	{
		avl_node_t **tree_node = NULL;
		if(!(tree_node = avl_search_key(&file->cache_tree, offset)))
			return read;
		avl_node_t *nd = *tree_node;
		struct page_cache *cache = nd->ptr;
		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;
		if(rest < 0) rest = 0;
		size_t amount = sizeofread - read < (size_t) rest ? sizeofread - read : (size_t) rest;
		memcpy((char*) buffer + read,  (char*) cache->page + cache_off, amount);
		offset += amount;
		read += amount;
	}
	return (ssize_t) read;
}
char *vfs_get_full_path(vfsnode_t *vnode, char *name)
{
	size_t size = strlen(vnode->name) + strlen(name) + (strlen(vnode->name) == 1 ? 0 : 1); 
	char *string = malloc(size);
	if(!string)
		return NULL;
	memset(string, 0, size);
	strcpy(string, vnode->name);
	if(strlen(vnode->name) != 1)	strcat(string, "/");
	strcat(string, name);
	return string;
}
ssize_t write_file_cache(void *buffer, size_t sizeofwrite, vfsnode_t *file, off_t offset)
{
	if(file->type != VFS_TYPE_FILE)
		return -1;
	if((size_t) offset > file->size)
		return 0;
	off_t off = (offset / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;
	do_file_caching(sizeofwrite, file, off, FILE_CACHING_WRITE);
	size_t wrote = 0;
	while(wrote != sizeofwrite)
	{
		avl_node_t **tree_node = NULL;
		if(!(tree_node = avl_search_key(&file->cache_tree, offset)))
			return wrote;
		avl_node_t *nd = *tree_node;
		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;
		if(rest < 0) rest = 0;
		size_t amount = sizeofwrite - wrote < (size_t) rest ? sizeofwrite - wrote : (size_t) rest;
		struct page_cache *cache = nd->ptr;
		memcpy((char*) cache->page + cache_off, (char*) buffer + wrote, amount);
		if(cache->size < cache_off + amount)
			cache->size = cache_off + amount;
		cache->dirty = 1;
		wakeup_sync_thread();
		offset += amount;
		wrote += amount;
	}
	return (ssize_t) wrote;
}
ssize_t send_vfs(const void *buf, size_t len, int flags, vfsnode_t *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return send_vfs(buf, len, flags, node->link);
	if(node->fops.send != NULL)
		return node->fops.send(buf, len, flags, node);
	return -ENOSYS;
}
int connect_vfs(const struct sockaddr *addr, socklen_t addrlen, vfsnode_t *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return connect_vfs(addr, addrlen, node->link);
	if(node->fops.connect != NULL)
		return node->fops.connect(addr, addrlen, node);
	return -ENOSYS;
}
int bind_vfs(const struct sockaddr *addr, socklen_t addrlen, vfsnode_t *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return connect_vfs(addr, addrlen, node->link);
	if(node->fops.bind != NULL)
		return node->fops.bind(addr, addrlen, node);
	return -ENOSYS;
}
ssize_t recvfrom_vfs(void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *slen, vfsnode_t *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return recvfrom_vfs(buf, len, flags, src_addr, slen, node->link);
	if(node->fops.recvfrom != NULL)
		return node->fops.recvfrom(buf, len, flags, src_addr, slen, node);
	return -ENOSYS;
}
