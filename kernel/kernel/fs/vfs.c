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
#include <onyx/mm/flush.h>
#include <onyx/vm.h>
#include <onyx/clock.h>

struct inode *fs_root = NULL;
struct inode *mount_list = NULL;

ssize_t write_file_cache(void *buffer, size_t sizeofwrite, struct inode *file, off_t offset);
bool inode_is_cacheable(struct inode *file);

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

struct page_cache_block *inode_do_caching(struct inode *inode, size_t offset, long flags)
{
	struct page_cache_block *block = NULL;
	/* Allocate a cache buffer */
	struct page *p = alloc_page(0);
	if(!p)
		return NULL;
	
	void *virt = PAGE_TO_VIRT(p);

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

struct page *vmo_inode_commit(size_t off, struct vm_object *vmo)
{
	struct inode *i = vmo->ino;

	struct page *page = alloc_page(0);
	if(!page)
		return NULL;

	page->off = off;
	void *ptr = PAGE_TO_VIRT(page);
	size_t to_read = i->i_size - off < PAGE_SIZE ? i->i_size - off : PAGE_SIZE;

	assert(to_read <= PAGE_SIZE);

	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	ssize_t read = read_vfs(
		READ_VFS_FLAG_IS_PAGE_CACHE,
		off,
		to_read,
		ptr,
		i);

	thread_change_addr_limit(old);

	if(read != (ssize_t) to_read)
	{
		printk("Error file read %lx bytes out of %lx, off %lx\n", read, to_read, off);
		perror("file");
		/* TODO: clean up */
		free_page(page);
		return NULL;
	}

	if(!add_cache_to_node(page, read, off, i))
	{
		printk("error add cache to node\n");
		free_page(page);
		return NULL;
	}

	return page;
}

int inode_create_vmo(struct inode *ino)
{
	ino->i_pages = vmo_create(ino->i_size, NULL);
	if(!ino->i_pages)
		return -1;
	ino->i_pages->commit = vmo_inode_commit;
	ino->i_pages->ino = ino;
	return 0;
}

struct page_cache_block *inode_get_cache_block(struct inode *ino, size_t off)
{
	if(!ino->i_pages)
	{
		if(inode_create_vmo(ino) < 0)
			return NULL;
	}

	if(off >= ino->i_pages->size)
	{
		ino->i_pages->size += (off - ino->i_pages->size) + PAGE_SIZE;
	}

	struct page *p = vmo_get(ino->i_pages, off, true);
	if(!p)
		return NULL;
	return p->cache;
}

struct page_cache_block *__inode_get_page_internal(struct inode *inode, size_t offset, long flags)
{
	off_t aligned_off = (offset / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;

	MUST_HOLD_LOCK(&inode->i_pages_lock);
	struct page_cache_block *b = inode_get_cache_block(inode, aligned_off);
	
	return b;
}

struct page_cache_block *inode_get_page(struct inode *inode, off_t offset, long flags)
{
	spin_lock_preempt(&inode->i_pages_lock);

	struct page_cache_block *b = __inode_get_page_internal(inode, offset, flags);

	if(b) page_pin(b->page);

	spin_unlock_preempt(&inode->i_pages_lock);

	return b;
}

void inode_update_atime(struct inode *ino)
{
	ino->i_atime = clock_get_posix_time();
	inode_mark_dirty(ino);
}

void inode_update_ctime(struct inode *ino)
{
	ino->i_ctime = clock_get_posix_time();
	inode_mark_dirty(ino);
}

void inode_update_mtime(struct inode *ino)
{
	ino->i_mtime = clock_get_posix_time();
	inode_mark_dirty(ino);
}

ssize_t do_actual_read(int flags, size_t offset, size_t len, void *buf, struct inode *ino)
{
	if(flags & READ_VFS_FLAG_IS_PAGE_CACHE || !inode_is_cacheable(ino))
		return ino->i_fops.read(flags, offset, len, buf, ino);
	
	return lookup_file_cache(buf, len, ino, offset);
}

bool is_invalid_length(size_t len)
{
	return ((ssize_t) len) < 0;
}

size_t clamp_length(size_t len)
{
	if(is_invalid_length(len))
		len = SSIZE_MAX;
	return len;
}

ssize_t read_vfs(int flags, size_t offset, size_t len, void *buffer, struct inode *ino)
{
	if(ino->i_type & VFS_TYPE_DIR)
		return errno = EISDIR, -1;
	
	if(!ino->i_fops.read)
		return errno = EIO, -1;
	
	len = clamp_length(len);

	ssize_t res = do_actual_read(flags, offset, len, buffer, ino);

	if(res >= 0)
	{
		inode_update_atime(ino);
	}

	return res;
}

ssize_t do_actual_write(size_t offset, size_t len, void *buffer, struct inode *ino)
{
	ssize_t st = 0;

	if(!inode_is_cacheable(ino))
	{
		st = ino->i_fops.write(offset, len, buffer, ino);
	}
	else
	{
		st = write_file_cache(buffer, len, ino, offset);
	}

	if(st >= 0)
	{
		/* Adjust the file size if needed */
		
		if(offset + len > ino->i_size)
		{
			ino->i_size = offset + len;
			inode_update_ctime(ino);
			inode_mark_dirty(ino);
		}

		inode_update_mtime(ino);
	}
	
	return st;
}

ssize_t write_vfs(size_t offset, size_t len, void *buffer, struct inode *ino)
{
	if(ino->i_type & VFS_TYPE_DIR)
		return errno = EISDIR, -1;
	
	if(!ino->i_fops.write)
		return errno = EIO, -1;

	len = clamp_length(len);
	
	ssize_t res = do_actual_write(offset, len, buffer, ino);

	return res;
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

char *readlink_vfs(struct inode *file)
{
	if(file->i_fops.readlink)
	{
		char *p = file->i_fops.readlink(file);
		if(p != NULL)
			inode_update_atime(file);
		
		return p;
	}

	return errno = EINVAL, NULL;
}

struct inode *follow_symlink(struct inode *file, struct inode *parent)
{
	char *symlink = readlink_vfs(file);
	if(!symlink)
		return NULL;
	
	struct inode *ret = open_vfs(parent, symlink);

	free(symlink);

	return ret;
}

bool file_can_access(struct inode *file, unsigned int perms)
{
	bool access_good = true;
	struct creds *c = creds_get();

	if(unlikely(c->euid == 0))
	{
		/* We're root: the access is good */
		goto out;
	}

	/* We're not root, let's do permission checking */

	/* Case 1 -  we're the owners of the file (file->uid == c->euid) */

	/* We're going to transform FILE_ACCESS_* constants (our perms var) into UNIX permissions */
	mode_t ino_perms;

	if(likely(file->i_uid == c->euid))
	{
		ino_perms = ((perms & FILE_ACCESS_READ) ? S_IRUSR : 0) |
                    ((perms & FILE_ACCESS_WRITE) ? S_IWUSR : 0) |
					((perms & FILE_ACCESS_EXECUTE) ? S_IXUSR : 0);
	}
	else if(file->i_gid == c->egid)
	{
		/* Case 2 - we're in the same group as the file */
		ino_perms = ((perms & FILE_ACCESS_READ) ? S_IRGRP : 0) |
                    ((perms & FILE_ACCESS_WRITE) ? S_IWGRP : 0) |
					((perms & FILE_ACCESS_EXECUTE) ? S_IXGRP : 0);
	}
	else
	{
		/* Case 3 - others permissions apply */
		ino_perms = ((perms & FILE_ACCESS_READ) ? S_IROTH : 0) |
                    ((perms & FILE_ACCESS_WRITE) ? S_IWOTH : 0) |
					((perms & FILE_ACCESS_EXECUTE) ? S_IXOTH : 0);
	}

	/* Now, test the calculated permission bits against the file's mode */

	access_good = (file->i_mode & ino_perms) == ino_perms;

#if 0
	if(!access_good)
	{
		printk("Halting for debug: ino perms %u, perms %u\n", ino_perms, file->i_mode);
		while(true) {}
	}
#endif
out:
	creds_put(c);
	return access_good;
}

struct inode *open_path_segment(char *segm, struct inode *node)
{
	/* Let's check if we have read access to the directory before doing anything */
	if(!file_can_access(node, FILE_ACCESS_READ))
	{
		return errno = EACCES, NULL;
	}

	struct inode *file = do_actual_open(node, segm);
	if(!file)
		return NULL;

	if(file->i_type == VFS_TYPE_SYMLINK)
	{
		struct inode *target = follow_symlink(file, node);
		if(!target)
			return NULL;
		
		close_vfs(file);
		file = target;
	}

	struct inode *mountpoint = NULL;
	if((mountpoint = mtable_lookup(file)))
	{
		close_vfs(file);
		file = mountpoint;
	}

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
		struct inode *new_node = open_path_segment(path, node);

		if(node != this)
			close_vfs(node);

		node = new_node;
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

	if(!file_can_access(base, FILE_ACCESS_WRITE))
	{
		close_vfs(base);
		errno = EACCES;
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

	if(!file_can_access(base, FILE_ACCESS_WRITE))
	{
		close_vfs(base);
		errno = EACCES;
		goto error;
	}

	if(base->i_fops.mkdir != NULL)
	{
		struct inode *ret = base->i_fops.mkdir(basename((char*) dup), mode, base);
		free(dup);
		return ret;
	}

	errno = ENOSYS;

error:
	free(dup);
	return NULL;
}

struct inode *mknod_vfs(const char *path, mode_t mode, dev_t dev, struct inode *this)
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

	if(!file_can_access(base, FILE_ACCESS_WRITE))
	{
		close_vfs(base);
		errno = EACCES;
		goto error;
	}

	if(base->i_fops.mknod != NULL)
	{
		struct inode *ret = base->i_fops.mknod(basename((char*) dup), mode, dev, base);
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
			return -errno;
		file = do_actual_open(file, basename((char*) path));
		if(!file)
			return -errno;
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

	if(copy_to_user(ubuf, buf, reclen) < 0)
	{
		errno = EFAULT;
		return -1;
	}

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
			if(!pos) return -1;
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

short default_poll(void *poll_table, short events, struct inode *node);

short poll_vfs(void *poll_file, short events, struct inode *node)
{
	if(node->i_fops.poll != NULL)
		return node->i_fops.poll(poll_file, events, node);
	
	return default_poll(poll_file, events, node);
}

struct page_cache_block *add_cache_to_node(void *ptr, size_t size, off_t offset,
	struct inode *node)
{
	struct page_cache_block *cache = add_to_cache(ptr, size, offset, node);
	if(!cache)
		return NULL;
	
	return cache;
}

bool inode_is_cacheable(struct inode *file)
{
	if(file->i_flags & INODE_FLAG_DONT_CACHE)
		return false;
	if(file->i_type != VFS_TYPE_FILE)
		return false;

	return true;
}

ssize_t lookup_file_cache(void *buffer, size_t sizeofread, struct inode *file,
	off_t offset)
{
	if(!inode_is_cacheable(file))
		return -1;

	if((size_t) offset > file->i_size)
		return 0;
	size_t read = 0;

	while(read != sizeofread)
	{
		struct page_cache_block *cache = inode_get_page(file, offset, FILE_CACHING_READ);

		if(!cache)
		{
			if(read)
			{
				return read;
			}
			else
			{
				errno = ENOMEM;
				return -1;
			}
		}

		struct page *page = cache->page;

		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;

		assert(rest > 0);
	
		size_t amount = sizeofread - read < (size_t) rest ?
			sizeofread - read : (size_t) rest;

		if(offset + amount > file->i_size)
		{
			amount = file->i_size - offset;
			if(copy_to_user((char*) buffer + read, (char*) cache->buffer +
				cache_off, amount) < 0)
			{
				page_unpin(page);
				errno = EFAULT;
				return -1;
			}

			page_unpin(page);
			return read + amount;
		}
		else
		{
			if(copy_to_user((char*) buffer + read,  (char*) cache->buffer +
				cache_off, amount) < 0)
			{
				page_unpin(page);
				errno = EFAULT;
				return -1;
			}
		}

		offset += amount;
		read += amount;

		page_unpin(page);
	}

	return (ssize_t) read;
}

ssize_t write_file_cache(void *buffer, size_t sizeofwrite, struct inode *file,
	off_t offset)
{
	if(!inode_is_cacheable(file))
		return -1;

	size_t wrote = 0;
	do
	{
		struct page_cache_block *cache = inode_get_page(file, offset,
						  FILE_CACHING_WRITE);

		if(cache == NULL)
		{
			if(wrote)
			{
				return wrote;
			}
			else
			{
				errno = ENOMEM;
				return -1;
			}
		}

		struct page *page = cache->page;

		off_t cache_off = offset % PAGE_CACHE_SIZE;
		off_t rest = PAGE_CACHE_SIZE - cache_off;

		size_t amount = sizeofwrite - wrote < (size_t) rest ?
			sizeofwrite - wrote : (size_t) rest;

		if(copy_from_user((char*) cache->buffer + cache_off, (char*) buffer +
			wrote, amount) < 0)
		{
			page_unpin(page);
			errno = EFAULT;
			return -1;
		}
	
		if(cache->size < cache_off + amount)
		{
			cache->size = cache_off + amount;
		}

		pagecache_dirty_block(cache);

		page_unpin(page);
	
		offset += amount;
		wrote += amount;

	} while(wrote != sizeofwrite);

	return (ssize_t) wrote;
}

ssize_t sendto_vfs(const void *buf, size_t len, int flags, struct sockaddr *addr,
	socklen_t addrlen, struct inode *node)
{
	if(node->i_fops.sendto != NULL)
		return node->i_fops.sendto(buf, len, flags, addr, addrlen, node);
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

int default_fallocate(int mode, off_t offset, off_t len, struct inode *file)
{
	/* VERY VERY VERY VERY VERY quick and dirty implementation to satisfy /bin/ld(.gold) */
	if(mode != 0)
		return -EINVAL;

	char *page = zalloc(PAGE_SIZE);
	if(!page)
	{
		return -ENOMEM;
	}

	size_t length_diff = (size_t) len;
	size_t off = off;
	while(length_diff != 0)
	{
		size_t to_write = length_diff >= PAGE_SIZE ? PAGE_SIZE : length_diff;

		size_t written = write_vfs(off, to_write, page, file);

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

int fallocate_vfs(int mode, off_t offset, off_t len, struct inode *file)
{
	if(0)
	{

	}
	else
		return default_fallocate(mode, offset, len, file);

	return -EINVAL;
}

int symlink_vfs(const char *dest, struct inode *inode)
{
	if(!file_can_access(inode, FILE_ACCESS_WRITE))
		return -EACCES;

	if(inode->i_fops.symlink != NULL)
		return inode->i_fops.symlink(dest, inode);
	return -ENOSYS;
}

void inode_destroy_page_caches(struct inode *inode)
{
	if(inode->i_pages)
		vmo_unref(inode->i_pages);
}


void inode_release(struct object *object)
{
	struct inode *inode = (struct inode *) object;

	if(inode->i_sb)
	{
		assert(inode->i_sb != NULL);

		/* Remove the inode from its superblock */
		superblock_remove_inode(inode->i_sb, inode);
	}

	if(inode->i_flags & INODE_FLAG_DIRTY)
		flush_remove_inode(inode);

	if(inode->i_fops.close != NULL)
		inode->i_fops.close(inode);

	inode_destroy_page_caches(inode);

	free(inode);
}

struct inode *inode_create(void)
{
	struct inode *inode = zalloc(sizeof(*inode));

	if(!inode)
		return NULL;

	/* Don't release inodes immediately */
	object_init(&inode->i_object, inode_release);

	return inode;
}

int link_vfs(struct inode *target, const char *name, struct inode *dir)
{
	if(!file_can_access(dir, FILE_ACCESS_WRITE))
		return -EACCES;

	if(dir->i_fops.link)
		return dir->i_fops.link(target, name, dir);
	return -EINVAL;
}

int unlink_vfs(const char *name, int flags, struct inode *node)
{
	if(!file_can_access(node, FILE_ACCESS_WRITE))
		return -EACCES;
	if(node->i_fops.link)
		return node->i_fops.unlink(name, flags, node);
	return -EINVAL;
}

void inode_mark_dirty(struct inode *ino)
{
	unsigned long old_flags = __sync_fetch_and_or(&ino->i_flags, INODE_FLAG_DIRTY);

	__sync_synchronize();

	if(old_flags & INODE_FLAG_DIRTY)
		return;

	flush_add_inode(ino);	
}

int inode_flush(struct inode *ino)
{
	struct superblock *sb = ino->i_sb;

	if(!sb || !sb->flush_inode)
		return 0;
	
	return sb->flush_inode(ino);
}
