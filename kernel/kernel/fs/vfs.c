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
#include <onyx/sysfs.h>
#include <onyx/fnv.h>
#include <onyx/object.h>
#include <onyx/process.h>
#include <onyx/dentry.h>

struct inode *fs_root = NULL;
struct inode *mount_list = NULL;
ssize_t write_file_cache(void *buffer, size_t sizeofwrite, struct inode *file, off_t offset);

#define FILE_CACHING_READ	(0 << 0)
#define FILE_CACHING_WRITE	(1 << 0)

struct filesystem_root
{
	struct object object;
	struct inode *inode;
	struct dentry *root_dentry;
};

struct filesystem_root boot_root = {0};

int vfs_init(void)
{
	object_init(&boot_root.object, NULL);
	//dentry_init();

	return 0;
}

struct filesystem_root *get_filesystem_root(void)
{
	struct process *p = get_current_process();
	if(!p)
		return &boot_root;

	return &boot_root;
}

struct inode *get_fs_root(void)
{
	struct filesystem_root *root = get_filesystem_root();

	return root->inode;
}

struct page_cache_block *inode_do_caching(struct inode *inode, off_t offset, long flags)
{
	struct page_cache_block *block = NULL;
	/* Allocate a cache buffer */
	struct page *p = alloc_page(0);
	if(!p)
		return NULL;
	
	void *virt = PHYS_TO_VIRT(p->paddr);

	/* The size may be lesser than PAGE_SIZE, because we may reach EOF
	 * before reading a whole page */

	ssize_t size = inode->i_fops.read(0, offset, PAGE_SIZE, virt, inode);

	if(size <= 0 && !(flags & FILE_CACHING_WRITE))
	{
		free_page(p);
		return NULL;
	}

	/* Add the cache block */
	block = add_cache_to_node(p, (size_t) size, offset, inode);

	/* Now the block might be added, return. We don't need to check for
	 * null
	*/

	return block;
}

#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
uint32_t crc32_calculate(uint8_t *ptr, size_t len);

#endif

struct page_cache_block *__inode_get_page_internal(struct inode *inode, off_t offset, long flags)
{
	off_t aligned_off = (offset / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;
	fnv_hash_t hash = fnv_hash(&aligned_off, sizeof(offset));

	struct page_cache_block *b = inode->i_pages[hash % VFS_PAGE_HASHTABLE_ENTRIES];

	/* Note: This should run with the pages_lock held */
	for(; b; b = b->next_inode)
	{
		if(b->offset <= offset && b->offset + (off_t) PAGE_CACHE_SIZE > offset)
		{
			#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
			assert(b->integrity == crc32_calculate(b->buffer, b->size));
			#endif
			return b;
		}
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
	spin_lock_preempt(&inode->i_pages_lock);

	struct page_cache_block *b = __inode_get_page(inode, offset);

	if(!b)
	{
		spin_unlock_preempt(&inode->i_pages_lock);
	}

	return b;
}

size_t read_vfs(int flags, size_t offset, size_t sizeofread, void* buffer, struct inode* this)
{
	if(this->i_type & VFS_TYPE_DIR)
		return errno = EISDIR, -1;
	if(this->i_fops.read != NULL)
	{
		ssize_t status;
		/* If caching failed, just do the normal way */
		if((status = lookup_file_cache(buffer, sizeofread, this, offset)) < 0)
			return this->i_fops.read(flags, offset, sizeofread, buffer, this);
		return status;
	}
	return errno = ENOSYS;
}

size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, struct inode* this)
{
	if(this->i_fops.write != NULL)
	{
		ssize_t status;
		/* If caching failed, just do the normal way */
		if((status = write_file_cache(buffer, sizeofwrite, this, offset)) < 0)
			return this->i_fops.write(offset, sizeofwrite, buffer, this);
		if(offset + sizeofwrite > this->i_size)
		{
			this->i_size = offset + sizeofwrite;
		}

		return status;
	}

	return errno = ENOSYS;
}

int ioctl_vfs(int request, char *argp, struct inode *this)
{
	if(this->i_fops.ioctl != NULL)
		return this->i_fops.ioctl(request, (void*) argp, this);
	return -ENOSYS;
}

void close_vfs(struct inode* this)
{
	object_unref(&this->i_object);
}

struct inode *do_actual_open(struct inode *this, const char *name)
{
	assert(this != NULL);

	if(this->i_fops.open != NULL)
	{
		struct inode *i = this->i_fops.open(this, name);
		
		if(i)
		{
			if(i->i_fops.on_open)
			{
				if(i->i_fops.on_open(i) < 0)
				{
					close_vfs(i);
					return NULL;
				}
			}
		}

		return i;
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

	/* Get a new ref to the node */
	if(node == this)
		object_ref(&node->i_object);
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

	if(base->i_fops.creat != NULL)
	{
		struct inode *ret = base->i_fops.creat(basename((char*) dup), mode, base);
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

	if(this->i_fops.mkdir != NULL)
	{
		struct inode *ret = this->i_fops.mkdir(basename((char*) dup), mode, base);
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
	
	if(strcmp((char*) path, "/") == 0)
	{
		if(boot_root.inode)
		{
			object_unref(&boot_root.inode->i_object);
		}

		boot_root.inode = fsroot;
	}
	else
	{
		struct inode *file = open_vfs(get_fs_root(), dirname((char*) path));
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
	if(file->i_fops.getdirent != NULL)
		return file->i_fops.getdirent(buf, off, file);
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
	if(!(this->i_type & VFS_TYPE_DIR))
		return errno = ENOTDIR, -1;
	
	/*printk("Seek: %lu\n", off);
	printk("Count: %u\n", count);*/
	struct dirent buf;
	unsigned int pos = 0;
	
	while(pos < count)
	{
		off_t of = do_getdirent(&buf, off, this);
		
		//printk("Dirent: %s\n", buf.d_name);
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
		if(written == (unsigned int) -1)
		{
			if(!pos) return errno = EINVAL, -1;
			else
				return pos;
		}

		pos += written;
		dirp = (void*) (char *) dirp + written;
		off = of;
		ret->read = pos;
		ret->new_off = off;
	}

	return pos; 
}

int stat_vfs(struct stat *buf, struct inode *node)
{
	if(node->i_fops.stat != NULL)
		return node->i_fops.stat(buf, node);
	
	return errno = ENOSYS, (unsigned int) -1;
}


void add_to_page_hashtable(struct page_cache_block *cache, struct inode *node)
{
	fnv_hash_t hash = fnv_hash(&cache->offset, sizeof(cache->offset));

	struct page_cache_block **pp = &node->i_pages[hash % VFS_PAGE_HASHTABLE_ENTRIES];

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
	if(file->i_type != VFS_TYPE_FILE)
		return -1;
	if((size_t) offset > file->i_size)
		return 0;
	size_t read = 0;

	while(read != sizeofread)
	{
		struct page_cache_block *cache = inode_get_page(file, offset);

		if(!cache)
		{
			if(read)
				return read;
			else
				return -ENOMEM;
		}

		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;

		assert(rest > 0);
	
		size_t amount = sizeofread - read < (size_t) rest ?
			sizeofread - read : (size_t) rest;

		if(offset + amount > file->i_size)
		{
			amount = file->i_size - offset;
			memcpy((char*) buffer + read,  (char*) cache->buffer +
				cache_off, amount);
			spin_unlock_preempt(&file->i_pages_lock);
			return read + amount;
		}
		else
			memcpy((char*) buffer + read,  (char*) cache->buffer +
				cache_off, amount);
		offset += amount;
		read += amount;

		spin_unlock_preempt(&file->i_pages_lock);

	}
	return (ssize_t) read;
}

ssize_t write_file_cache(void *buffer, size_t sizeofwrite, struct inode *file,
	off_t offset)
{
	if(file->i_type != VFS_TYPE_FILE)
		return -1;

	size_t wrote = 0;
	do
	{
		
		spin_lock(&file->i_pages_lock);
		struct page_cache_block *cache =
			__inode_get_page_internal(file, offset,
						  FILE_CACHING_WRITE);

		if(cache == NULL)
		{
			spin_unlock(&file->i_pages_lock);
			if(wrote)
			{
				wakeup_sync_thread();
				return wrote;
			}
			else
				return -ENOMEM;
		}

		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;

		size_t amount = sizeofwrite - wrote < (size_t) rest ?
			sizeofwrite - wrote : (size_t) rest;

		memcpy((char*) cache->buffer + cache_off, (char*) buffer +
			wrote, amount);
	
		if(cache->size < cache_off + amount)
		{
			cache->size = cache_off + amount;
		}
	
		cache->dirty = 1;

		offset += amount;
		wrote += amount;

		spin_unlock(&file->i_pages_lock);
	} while(wrote != sizeofwrite);

	wakeup_sync_thread();

	return (ssize_t) wrote;
}

ssize_t send_vfs(const void *buf, size_t len, int flags, struct inode *node)
{
	if(node->i_fops.send != NULL)
		return node->i_fops.send(buf, len, flags, node);
	return -ENOSYS;
}

int connect_vfs(const struct sockaddr *addr, socklen_t addrlen, struct inode *node)
{
	if(node->i_fops.connect != NULL)
		return node->i_fops.connect(addr, addrlen, node);
	return -ENOSYS;
}

int bind_vfs(const struct sockaddr *addr, socklen_t addrlen, struct inode *node)
{
	if(node->i_fops.bind != NULL)
		return node->i_fops.bind(addr, addrlen, node);
	return -ENOSYS;
}

ssize_t recvfrom_vfs(void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *slen, struct inode *node)
{
	if(node->i_fops.recvfrom != NULL)
		return node->i_fops.recvfrom(buf, len, flags, src_addr, slen,
			node);
	return -ENOSYS;
}

int default_ftruncate(off_t length, struct inode *vnode)
{
	if(length < 0)
		return -EINVAL;
	
	if((size_t) length <= vnode->i_size)
	{
		/* Possible memory/disk leak, but filesystems should handle it */
		vnode->i_size = (size_t) length;
		return 0;
	}

	char *page = zalloc(PAGE_SIZE);
	if(!page)
	{
		return -ENOMEM;
	}

	size_t length_diff = (size_t) length - vnode->i_size;
	size_t off = vnode->i_size;
	while(length_diff != 0)
	{
		size_t to_write = length_diff >= PAGE_SIZE ? PAGE_SIZE : length_diff;

		size_t written = write_vfs(off, to_write, page, vnode);

		if(written != to_write)
		{
			free(page);
			return (int) written;
		}

		off += to_write;
		length_diff -= to_write;
	}

	free(page);

	return 0;
}

int ftruncate_vfs(off_t length, struct inode *vnode)
{
	if(vnode->i_fops.ftruncate != NULL)
		return vnode->i_fops.ftruncate(length, vnode);
	else
	{
		return default_ftruncate(length, vnode);
	}

	return -ENOSYS;
}

int symlink_vfs(const char *dest, struct inode *inode)
{
	if(inode->i_fops.symlink != NULL)
		return inode->i_fops.symlink(dest, inode);
	return -ENOSYS;
}

struct page *file_get_page(struct inode *ino, off_t offset)
{
	off_t off = (offset / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;

	struct page_cache_block *cache = inode_get_page(ino, off);

	/* TODO: questionablecode.jpeg */
	spin_unlock_preempt(&ino->i_pages_lock);

	return cache != NULL ? cache->page : NULL;
}

void inode_destroy_page_caches(struct inode *inode)
{
	for(size_t i = 0; i < VFS_PAGE_HASHTABLE_ENTRIES; i++)
	{
		if(!inode->i_pages[i])
			continue;
		
		struct page_cache_block *block = inode->i_pages[i];

		while(block)
		{
			struct page_cache_block *old = block;
			block = block->next_inode;
			
			page_cache_destroy(old);
		}
	}
}

void inode_release(struct object *object)
{
	struct inode *inode = (struct inode *) object;

	assert(inode->i_sb != NULL);

	/* Remove the inode from its superblock */
	superblock_remove_inode(inode->i_sb, inode);

	if(inode->i_fops.close != NULL)
		inode->i_fops.close(inode);

	inode_destroy_page_caches(inode);

	/*printk("Inode %p destroyed\n", inode);
	printk("Refcount %lu\n", inode->i_object.ref.refcount);*/

	free(inode);
}

struct inode *inode_create(void)
{
	struct inode *inode = zalloc(sizeof(*inode));

	if(!inode)
		return NULL;

	/* Don't release inodes immediately */
	object_init(&inode->i_object, NULL);

	return inode;
}