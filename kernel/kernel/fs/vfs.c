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

#include <onyx/avl.h>
#include <onyx/panic.h>
#include <onyx/vfs.h>
#include <onyx/dev.h>
#include <onyx/pagecache.h>
#include <onyx/log.h>
#include <onyx/mtable.h>
#include <onyx/atomic.h>

static avl_node_t **avl_search_key(avl_node_t **t, uintptr_t key);
struct inode *fs_root = NULL;
struct inode *mount_list = NULL;
ssize_t write_file_cache(void *buffer, size_t sizeofwrite, struct inode *file, off_t offset);

#define FILE_CACHING_WRITE	1
ssize_t do_file_caching(size_t sizeofread, struct inode *this, off_t offset, int flags)
{
	if(this->type != VFS_TYPE_FILE) /* Only VFS_TYPE_FILE files can be cached */
		return -1;

	void *cache = zalloc(PAGE_CACHE_SIZE);
	if(!cache)
		return -1;

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

int vfs_init(void)
{
	mount_list = malloc(sizeof(struct inode));
	if(!mount_list)
		panic("Error while allocating the mount list!\n");
	memset(mount_list, 0, sizeof(struct inode));
	if(!mount_list)
		return 1;
	fs_root = mount_list;
	memset(fs_root, 0, sizeof(struct inode));
	fs_root->refcount++;
	return 0;
}

size_t read_vfs(int flags, size_t offset, size_t sizeofread, void* buffer, struct inode* this)
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

size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, struct inode* this)
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

int ioctl_vfs(int request, char *argp, struct inode *this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return ioctl_vfs(request, argp, this->link);
	if(this->fops.ioctl != NULL)
		return this->fops.ioctl(request, (void*) argp, this);
	return -ENOSYS;
}

void close_vfs(struct inode* this)
{
	if(this->type & VFS_TYPE_MOUNTPOINT)
		close_vfs(this->link);
	if(this->fops.close != NULL)
		this->fops.close(this);

	if(atomic_dec(&this->refcount, 1) == 0)
	{
		if(this->i_sb)
			superblock_remove_inode(this->i_sb, this);
		free(this);
	}
}

struct inode *do_actual_open(struct inode *this, const char *name)
{
	assert(this != NULL);

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

struct inode *open_path_segment(char *segm, struct inode *node)
{
	struct inode *file = do_actual_open(node, segm);
	if(!file)
		return NULL;
	struct inode *mountpoint = NULL;
	if((mountpoint = mtable_lookup(file)))
		file = mountpoint;
	return file;
}

struct inode *open_vfs(struct inode* this, const char *name)
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
	struct inode *node = this;
	
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

struct inode *creat_vfs(struct inode *this, const char *path, int mode)
{
	char *dup = strdup(path);
	if(!dup)
		return errno = ENOMEM, NULL;

	char *dir = dirname((char*) dup);

	struct inode *base;
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
		struct inode *node = creat_vfs(base->link, basename((char*) dup), mode);
		free(dup);
		return node;
	}

	if(this->fops.creat != NULL)
	{
		struct inode *ret = this->fops.creat(basename((char*) dup), mode, base);
		free(dup);
		return ret;
	}

	errno = ENOSYS;

error:
	free(dup);
	return NULL;
}

struct inode *mkdir_vfs(const char *path, mode_t mode, struct inode *this)
{
	char *dup = strdup(path);
	if(!dup)
		return errno = ENOMEM, NULL;

	char *dir = dirname((char*) dup);
	struct inode *base;
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
		struct inode *node = mkdir_vfs(basename((char*) dup), mode, base->link);
		free(dup);
		return node;
	}

	if(this->fops.mkdir != NULL)
	{
		struct inode *ret = this->fops.mkdir(basename((char*) dup), mode, base);
		free(dup);
		return ret;
	}

	errno = ENOSYS;

error:
	free(dup);
	return NULL;
}

int mount_fs(struct inode *fsroot, const char *path)
{
	assert(fsroot != NULL);

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
		struct inode *file = open_vfs(fs_root, dirname((char*) path));
		if(!file)
			return -ENOENT;
		file = do_actual_open(file, basename((char*) path));
		if(!file)
			return -ENOENT;
		return mtable_mount(file, fsroot);
	}
	return 0;
}

off_t do_getdirent(struct dirent *buf, off_t off, struct inode *file)
{
	if(file->type & VFS_TYPE_MOUNTPOINT)
		return do_getdirent(buf, off, file->link);
	if(file->fops.getdirent != NULL)
		return file->fops.getdirent(buf, off, file);
	return -ENOSYS;
}

unsigned int putdir(struct dirent *buf, struct dirent *ubuf, unsigned int count)
{
	unsigned int reclen = buf->d_reclen;
	
	if(reclen > count)
		return errno = EINVAL, -1;
	/* TODO: Use copy_to_user() */
	memcpy(ubuf, buf, reclen);

	return reclen > count ? count : reclen;
}

off_t getdents_vfs(unsigned int count, putdir_t putdir,
	struct dirent* dirp, off_t off, struct inode *this)
{
	if(!(this->type & VFS_TYPE_DIR))
		return errno = ENOTDIR, -1;
	
	struct dirent buf;
	unsigned int pos = 0;
	
	while(pos < count)
	{
		off_t of = do_getdirent(&buf, off, this);
		
		if(of == 0)
			return 0; /* EOF, return EOF */
		if(of < 0)
			return errno = -of, -1; /* Error, return -1 with errno set */

		/* Put the dirent in the user-space buffer */
		unsigned int written = putdir(&buf, dirp, count);
		if(written == (unsigned int ) -1)
			return -1; /* Error, most likely out of buffer space */

		pos += written;
		dirp = (void*) (char *) dirp + written;
		off += of;
	}
	
	return off; 
}

int stat_vfs(struct stat *buf, struct inode *node)
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

static avl_node_t *avl_insert_key(avl_node_t **t, uintptr_t key, struct inode *vfs)
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
	if(key > ptr->key && key < ptr->key + PAGE_CACHE_SIZE)
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
	vfree(ptr->ptr, PAGE_CACHE_SIZE / PAGE_SIZE);
	free(ptr);
	*n = NULL;
	avl_balance_tree(tree);
	return 0;
}

void *add_cache_to_node(void *ptr, size_t size, off_t offset, struct inode *node)
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

ssize_t lookup_file_cache(void *buffer, size_t sizeofread, struct inode *file, off_t offset)
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
		if(offset + amount > file->size)
		{
			amount = file->size - offset;
			memcpy((char*) buffer + read,  (char*) cache->page + cache_off, amount);
			return read + amount;
		}
		else
			memcpy((char*) buffer + read,  (char*) cache->page + cache_off, amount);
		offset += amount;
		read += amount;
	}
	return (ssize_t) read;
}

char *vfs_get_full_path(struct inode *vnode, char *name)
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

ssize_t write_file_cache(void *buffer, size_t sizeofwrite, struct inode *file, off_t offset)
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

ssize_t send_vfs(const void *buf, size_t len, int flags, struct inode *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return send_vfs(buf, len, flags, node->link);
	if(node->fops.send != NULL)
		return node->fops.send(buf, len, flags, node);
	return -ENOSYS;
}

int connect_vfs(const struct sockaddr *addr, socklen_t addrlen, struct inode *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return connect_vfs(addr, addrlen, node->link);
	if(node->fops.connect != NULL)
		return node->fops.connect(addr, addrlen, node);
	return -ENOSYS;
}

int bind_vfs(const struct sockaddr *addr, socklen_t addrlen, struct inode *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return connect_vfs(addr, addrlen, node->link);
	if(node->fops.bind != NULL)
		return node->fops.bind(addr, addrlen, node);
	return -ENOSYS;
}

ssize_t recvfrom_vfs(void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *slen, struct inode *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return recvfrom_vfs(buf, len, flags, src_addr, slen, node->link);
	if(node->fops.recvfrom != NULL)
		return node->fops.recvfrom(buf, len, flags, src_addr, slen, node);
	return -ENOSYS;
}

int ftruncate_vfs(off_t length, struct inode *vnode)
{
	if(vnode->type & VFS_TYPE_MOUNTPOINT)
		return ftruncate_vfs(length, vnode);
	if(vnode->fops.ftruncate != NULL)
		return vnode->fops.ftruncate(length, vnode);
	return -ENOSYS;
}

int symlink_vfs(const char *dest, struct inode *inode)
{
	if(inode->type & VFS_TYPE_MOUNTPOINT)
		return symlink_vfs(dest, inode);
	if(inode->fops.symlink != NULL)
		return inode->fops.symlink(dest, inode);
	return -ENOSYS;
}

struct page *file_get_page(struct inode *ino, off_t offset)
{
	off_t off = (offset / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;
	do_file_caching(PAGE_CACHE_SIZE, ino, off, 0);

	avl_node_t **tree_node = NULL;
	if(!(tree_node = avl_search_key(&ino->cache_tree, off)))
		return NULL;
	avl_node_t *nd = *tree_node;
	struct page_cache *cache = nd->ptr;
	off_t off_from_cache = offset - off;
	
	return phys_to_page((uintptr_t) virtual2phys(cache->page) + off_from_cache);
}
