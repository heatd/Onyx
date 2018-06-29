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

#include <onyx/panic.h>
#include <onyx/vfs.h>
#include <onyx/dev.h>
#include <onyx/pagecache.h>
#include <onyx/log.h>
#include <onyx/mtable.h>
#include <onyx/atomic.h>
#include <onyx/sysfs.h>
#include <onyx/fnv.h>

struct inode *fs_root = NULL;
struct inode *mount_list = NULL;
ssize_t write_file_cache(void *buffer, size_t sizeofwrite, struct inode *file, off_t offset);

#define FILE_CACHING_READ	(0 << 0)
#define FILE_CACHING_WRITE	(1 << 0)


struct page_cache_block *inode_do_caching(struct inode *inode, off_t offset, long flags)
{
	struct page_cache_block *block = NULL;
	/* Allocate a cache buffer */
	void *cache = zalloc(PAGE_SIZE);
	if(!cache)
		return NULL;
	
	/* The size may be lesser than PAGE_SIZE, because we may reach EOF
	 * before reading a page */
	ssize_t size = inode->fops.read(0, offset, PAGE_SIZE, cache, inode);
	
	if(size <= 0 && !(flags & FILE_CACHING_WRITE))
		return NULL;

	if(flags & FILE_CACHING_WRITE)
		size = PAGE_CACHE_SIZE;

	/* Add the cache block */
	block = add_cache_to_node(cache, (size_t) size, offset, inode);

	/* Now the block might be added, return. We don't need to check for
	 * null
	*/

	/* Free the buffer before returning */
	free(cache);

	return block;
}

struct page_cache_block *__inode_get_page_internal(struct inode *inode, off_t offset, long flags)
{
	off_t aligned_off = (offset / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;
	fnv_hash_t hash = fnv_hash(&aligned_off, sizeof(offset));

	struct page_cache_block *b = inode->pages[hash % VFS_PAGE_HASHTABLE_ENTRIES];

	/* Note: This should run with the pages_lock held */
	for(; b; b = b->next_inode)
	{
		if(b->offset == offset ||
		  (b->offset < offset && b->offset + (off_t) b->size > offset))
			return b;
	}

	/* We don't release the lock if we didn't find anything on purpose.
	 * That job is left to inode_get_page, which does that work for non-inode
	 * code callers.
	*/
	
	/* Try to add it to the cache if it didn't exist before. */
	struct page_cache_block *block = inode_do_caching(inode, aligned_off, flags);

	return block;
}

struct page_cache_block *__inode_get_page(struct inode *inode, off_t offset)
{
	return __inode_get_page_internal(inode, offset, FILE_CACHING_READ);
}

struct page_cache_block *inode_get_page(struct inode *inode, off_t offset)
{
	acquire_spinlock(&inode->pages_lock);

	struct page_cache_block *b = __inode_get_page(inode, offset);

	if(!b)
	{
		off_t aligned_off = (offset / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;
		fnv_hash_t hash = fnv_hash(&aligned_off, sizeof(offset));
		unsigned int idx = hash % VFS_PAGE_HASHTABLE_ENTRIES;
		printk("idx[]: %p\n", inode->pages[idx]);
		printk("Aligned off %ld\nHash %u\n", aligned_off, idx);
		while(1);
		release_spinlock(&inode->pages_lock);
	}
	return b;
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
		/* If caching failed, just do the normal way */
		if((status = lookup_file_cache(buffer, sizeofread, this, offset)) < 0)
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
		/* If caching failed, just do the normal way */
		if((status = write_file_cache(buffer, sizeofwrite, this, offset)) < 0)
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

	if(base->fops.creat != NULL)
	{
		struct inode *ret = base->fops.creat(basename((char*) dup), mode, base);
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
		sysfs_mount();
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

unsigned int putdir(struct dirent *buf, struct dirent *ubuf,
	unsigned int count)
{
	unsigned int reclen = buf->d_reclen;
	
	if(reclen > count)
		return errno = EINVAL, -1;
	/* TODO: Use copy_to_user() */
	memcpy(ubuf, buf, reclen);

	return reclen > count ? count : reclen;
}

int getdents_vfs(unsigned int count, putdir_t putdir,
	struct dirent* dirp, off_t off, struct getdents_ret *ret,
	struct inode *this)
{
	if(!(this->type & VFS_TYPE_DIR))
		return errno = ENOTDIR, -1;
	struct dirent buf;
	unsigned int pos = 0;
	
	while(pos < count)
	{
		off_t of = do_getdirent(&buf, off, this);
		
		if(of == 0)
		{
			if(pos)
				return pos;
			return 0;
		}

		/* Error, return -1 with errno set */
		if(of < 0)
			return errno = -of, -1;

		/* Put the dirent in the user-space buffer */
		unsigned int written = putdir(&buf, dirp, count);
		/* Error, most likely out of buffer space */
		if(written == (unsigned int ) -1)
		{
			if(!pos) return errno = EINVAL, -1;
			else
				return pos;
		}

		pos += written;
		dirp = (void*) (char *) dirp + written;
		off++;
		ret->read = pos;
		ret->new_off = off;
	}

	return pos; 
}

int stat_vfs(struct stat *buf, struct inode *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return stat_vfs(buf, node->link);
	if(node->fops.stat != NULL)
		return node->fops.stat(buf, node);
	
	return errno = ENOSYS, (unsigned int) -1;
}


void add_to_page_hashtable(struct page_cache_block *cache, struct inode *node)
{
	fnv_hash_t hash = fnv_hash(&cache->offset, sizeof(cache->offset));

	struct page_cache_block **pp = &node->pages[hash % VFS_PAGE_HASHTABLE_ENTRIES];

	while(*pp)
		pp = &(*pp)->next_inode;
	*pp = cache;
}

struct page_cache_block *add_cache_to_node(void *ptr, size_t size, off_t offset,
	struct inode *node)
{
	struct page_cache_block *cache = add_to_cache(ptr, size, offset, node);
	if(!cache)
		return NULL;
	
	add_to_page_hashtable(cache, node);
	return cache;
}

ssize_t lookup_file_cache(void *buffer, size_t sizeofread, struct inode *file,
	off_t offset)
{
	if(file->type != VFS_TYPE_FILE)
		return -1;
	if((size_t) offset > file->size)
		return 0;
	size_t read = 0;

	while(read != sizeofread)
	{
		struct page_cache_block *cache = inode_get_page(file, offset);

		if(!cache)
		{
			printf("Bad offset %ld\n", offset);

			/* TODO: Recover */
			assert(cache != NULL);
		}

		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;
		if(rest < 0) rest = 0;
		size_t amount = sizeofread - read < (size_t) rest ?
			sizeofread - read : (size_t) rest;
		if(offset + amount > file->size)
		{
			amount = file->size - offset;
			memcpy((char*) buffer + read,  (char*) cache->buffer +
				cache_off, amount);
			release_spinlock(&file->pages_lock);
			return read + amount;
		}
		else
			memcpy((char*) buffer + read,  (char*) cache->buffer +
				cache_off, amount);
		offset += amount;
		read += amount;

		release_spinlock(&file->pages_lock);

	}
	return (ssize_t) read;
}

char *vfs_get_full_path(struct inode *vnode, char *name)
{
	size_t size = strlen(vnode->name) + strlen(name) + (strlen(vnode->name)
		== 1 ? 0 : 1); 
	char *string = malloc(size);
	if(!string)
		return NULL;
	memset(string, 0, size);
	strcpy(string, vnode->name);
	if(strlen(vnode->name) != 1)	strcat(string, "/");
	strcat(string, name);
	return string;
}

ssize_t write_file_cache(void *buffer, size_t sizeofwrite, struct inode *file,
	off_t offset)
{
	if(file->type != VFS_TYPE_FILE)
		return -1;
	if((size_t) offset > file->size)
		return 0;
	
	size_t wrote = 0;
	while(wrote != sizeofwrite)
	{
		
		acquire_spinlock(&file->pages_lock);
		struct page_cache_block *cache =
			__inode_get_page_internal(file, offset,
						  FILE_CACHING_WRITE);

		/* TODO: Recover */
		assert(cache != NULL);

		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;
		if(rest < 0) rest = 0;
		size_t amount = sizeofwrite - wrote < (size_t) rest ?
			sizeofwrite - wrote : (size_t) rest;
		memcpy((char*) cache->buffer + cache_off, (char*) buffer +
			wrote, amount);
		if(cache->size < cache_off + amount)
			cache->size = cache_off + amount;
		cache->dirty = 1;
		wakeup_sync_thread();
		offset += amount;
		wrote += amount;

		release_spinlock(&file->pages_lock);
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

ssize_t recvfrom_vfs(void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *slen, struct inode *node)
{
	if(node->type & VFS_TYPE_MOUNTPOINT)
		return recvfrom_vfs(buf, len, flags, src_addr, slen,
			node->link);
	if(node->fops.recvfrom != NULL)
		return node->fops.recvfrom(buf, len, flags, src_addr, slen,
			node);
	return -ENOSYS;
}

int default_ftruncate(off_t length, struct inode *vnode)
{
	
	if(length < 0)
		return -EINVAL;
	
	if((size_t) length <= vnode->size)
	{
		/* Possible memory/disk leak, but filesystems should handle it */
		vnode->size = (size_t) length;
		return 0;
	}

	char *page = zalloc(PAGE_SIZE);
	if(!page)
	{
		return -ENOMEM;
	}

	size_t length_diff = (size_t) length - vnode->size;
	size_t off = vnode->size;
	while(length_diff != 0)
	{
		size_t to_write = length_diff >= PAGE_SIZE ? PAGE_SIZE : length_diff;

		size_t written = write_vfs(off, to_write, page, vnode);

		if(written != to_write)
		{
			return (int) written;
		}

		off += to_write;
		length_diff -= to_write;
	}

	return 0;
}

int ftruncate_vfs(off_t length, struct inode *vnode)
{
	if(vnode->type & VFS_TYPE_MOUNTPOINT)
		return ftruncate_vfs(length, vnode);
	if(vnode->fops.ftruncate != NULL)
		return vnode->fops.ftruncate(length, vnode);
	else
	{
		return default_ftruncate(length, vnode);
	}

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

	struct page_cache_block *cache = inode_get_page(ino, off);

	/* TODO: questionablecode.jpeg */
	release_spinlock(&ino->pages_lock);

	return cache != NULL ? cache->page : NULL;
}
