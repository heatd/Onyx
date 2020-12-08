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
#include <limits.h>

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
#include <onyx/cpu.h>
#include <onyx/buffer.h>

struct file *fs_root = NULL;
struct file *mount_list = NULL;

bool inode_is_cacheable(struct inode *file);

struct filesystem_root boot_root = {0};

int vfs_init(void)
{
	object_init(&boot_root.object, NULL);
	dentry_init();

	return 0;
}

struct filesystem_root *get_filesystem_root(void)
{
	struct process *p = get_current_process();
	if(!p)
		return &boot_root;

	return &boot_root;
}

struct file *get_fs_root(void)
{
	struct filesystem_root *root = get_filesystem_root();

	return root->file;
}

#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
uint32_t crc32_calculate(uint8_t *ptr, size_t len);

#endif

/* This function trims the part of the page that wasn't read in(because the segment of
 * the file is smaller than PAGE_SIZE).
 */
static void zero_rest_of_page(struct page *page, size_t to_read)
{
	unsigned char *buf = PAGE_TO_VIRT(page) + to_read;

	size_t to_zero = PAGE_SIZE - to_read;

	memset(buf, 0, to_zero);
} 

vmo_status_t vmo_inode_commit(struct vm_object *vmo, size_t off, struct page **ppage)
{
	struct inode *i = vmo->ino;

	struct page *page = alloc_page(PAGE_ALLOC_NO_ZERO);
	if(!page)
		return VMO_STATUS_OUT_OF_MEM;

	page->flags |= PAGE_FLAG_BUFFER;

	size_t to_read = i->i_size - off < PAGE_SIZE ? i->i_size - off : PAGE_SIZE;

	assert(to_read <= PAGE_SIZE);

	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	assert(i->i_fops->readpage != NULL);
	ssize_t read = i->i_fops->readpage(page, off, i);

	thread_change_addr_limit(old);

	if(read != (ssize_t) to_read)
	{
#if 0
		printk("Error file read %lx bytes out of %lx, off %lx\n", read, to_read, off);
		perror("file");
#endif
		free_page(page);
		return VMO_STATUS_BUS_ERROR;
	}

	zero_rest_of_page(page, to_read);

	if(!pagecache_create_cache_block(page, read, off, i))
	{
		free_page(page);
		return VMO_STATUS_OUT_OF_MEM;
	}

	*ppage = page;

	return VMO_STATUS_OK;
}

void inode_free_page(struct vm_object *vmo, struct page *page)
{
	struct page_cache_block *b = page->cache;
	if(page->flags & PAGE_FLAG_DIRTY)
	{
		flush_sync_one(&b->fobj);
	}

	page_destroy_block_bufs(page);

	page->cache = NULL;
	free(b);
}

const struct vm_object_ops inode_vmo_ops = 
{
	.commit = vmo_inode_commit,
	.free_page = inode_free_page
};

int inode_create_vmo(struct inode *ino)
{
	ino->i_pages = vmo_create(ino->i_size, NULL);
	if(!ino->i_pages)
		return -1;
	ino->i_pages->ops = &inode_vmo_ops;
	ino->i_pages->ino = ino;
	return 0;
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

ssize_t do_actual_read(size_t offset, size_t len, void *buf, struct file *file)
{
	if(!inode_is_cacheable(file->f_ino))
		return file->f_ino->i_fops->read(offset, len, buf, file);
	
	return file_read_cache(buf, len, file->f_ino, offset);
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

ssize_t read_vfs(size_t offset, size_t len, void *buffer, struct file *file)
{
	struct inode *ino = file->f_ino;
	if(ino->i_type & VFS_TYPE_DIR)
		return errno = EISDIR, -1;
	
	if(!ino->i_fops->readpage && !ino->i_fops->read)
		return errno = EIO, -1;

	len = clamp_length(len);

	ssize_t res = do_actual_read(offset, len, buffer, file);

	if(res >= 0)
	{
		inode_update_atime(ino);
	}

	return res;
}

ssize_t do_actual_write(size_t offset, size_t len, void *buffer, struct file *f)
{
	ssize_t st = 0;
	struct inode *ino = f->f_ino;

	if(!inode_is_cacheable(ino))
	{
		st = ino->i_fops->write(offset, len, buffer, f);
	}
	else
	{
		st = file_write_cache(buffer, len, ino, offset);
	}

	if(st >= 0)
	{
		inode_update_mtime(ino);
	}
	
	return st;
}

ssize_t write_vfs(size_t offset, size_t len, void *buffer, struct file *f)
{
	struct inode *ino = f->f_ino;
	if(ino->i_type & VFS_TYPE_DIR)
		return errno = EISDIR, -1;
	
	if(!ino->i_fops->writepage && !ino->i_fops->write)
		return errno = EIO, -1;

	len = clamp_length(len);
	
	ssize_t res = do_actual_write(offset, len, buffer, f);

	return res;
}

int ioctl_vfs(int request, char *argp, struct file *this)
{
	if(this->f_ino->i_fops->ioctl != NULL)
		return this->f_ino->i_fops->ioctl(request, (void*) argp, this);
	return -ENOTTY;
}

void close_vfs(struct inode *this)
{
	inode_unref(this);
}

char *readlink_vfs(struct file *file)
{
	if(file->f_ino->i_type != VFS_TYPE_SYMLINK)
		return errno = EINVAL, NULL;

	if(file->f_ino->i_fops->readlink)
	{
		char *p = file->f_ino->i_fops->readlink(file);
		if(p != NULL)
			inode_update_atime(file->f_ino);
		
		return p;
	}

	return errno = EINVAL, NULL;
}

bool inode_can_access(struct inode *file, unsigned int perms)
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

bool file_can_access(struct file *file, unsigned int perms)
{
	return inode_can_access(file->f_ino, perms);
}

off_t do_getdirent(struct dirent *buf, off_t off, struct file *file)
{
	/* FIXME: Detect when we're trying to list unlinked directories, lock the dentry, etc... */
	if(file->f_ino->i_fops->getdirent != NULL)
		return file->f_ino->i_fops->getdirent(buf, off, file);
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
	struct file *f)
{
	if(!(f->f_ino->i_type & VFS_TYPE_DIR))
		return errno = ENOTDIR, -1;

	if(!file_can_access(f, FILE_ACCESS_READ))
		return errno = EACCES, -1;
	
	/*printk("Seek: %lu\n", off);
	printk("Count: %u\n", count);*/
	struct dirent buf;
	unsigned int pos = 0;
	
	while(pos < count)
	{
		off_t of = do_getdirent(&buf, off, f);
		
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
		unsigned int written = putdir(&buf, dirp, count - pos);
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

int default_stat(struct stat *buf, struct file *f)
{
	struct inode *ino = f->f_ino;

	buf->st_atime = ino->i_atime;
	buf->st_ctime = ino->i_ctime;
	buf->st_mtime = ino->i_mtime;

	buf->st_blksize = ino->i_sb ? ino->i_sb->s_block_size : PAGE_SIZE;
	buf->st_blocks = ino->i_blocks;
	buf->st_dev = ino->i_dev;
	buf->st_gid = ino->i_gid;
	buf->st_uid = ino->i_uid;
	buf->st_ino = ino->i_inode;
	buf->st_mode = ino->i_mode;
	buf->st_nlink = ino->i_nlink;
	buf->st_rdev = ino->i_rdev;
	buf->st_size = ino->i_size;

	return 0;
}

int stat_vfs(struct stat *buf, struct file *node)
{
	if(node->f_ino->i_fops->stat != NULL)
		return node->f_ino->i_fops->stat(buf, node);
	else
	{
		return default_stat(buf, node);
	}
}

short default_poll(void *poll_table, short events, struct file *node);

short poll_vfs(void *poll_file, short events, struct file *node)
{
	if(node->f_ino->i_fops->poll != NULL)
		return node->f_ino->i_fops->poll(poll_file, events, node);
	
	return default_poll(poll_file, events, node);
}

bool inode_is_cacheable(struct inode *ino)
{
	if(ino->i_flags & INODE_FLAG_DONT_CACHE)
		return false;
	
	/* TODO: Find a better solution here. Set a flag for when the inode has a cache maybe?
	 * Or use the .read and .write function pointers.
	 */

	if(ino->i_type != VFS_TYPE_FILE && ino->i_type != VFS_TYPE_DIR && ino->i_type != VFS_TYPE_SYMLINK)
		return false;

	return true;
}

int default_ftruncate(off_t length, struct file *f)
{
	if(length < 0)
		return -EINVAL;
	struct inode *vnode = f->f_ino;
	
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

	printk("Default ftruncate\n");

	size_t length_diff = (size_t) length - vnode->i_size;
	size_t off = vnode->i_size;

	while(length_diff != 0)
	{
		size_t to_write = length_diff >= PAGE_SIZE ? PAGE_SIZE : length_diff;

		unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
		size_t written = write_vfs(off, to_write, page, f);
		
		thread_change_addr_limit(old);
		if(written != to_write)
		{
			free(page);
			return -errno;
		}

		off += to_write;
		length_diff -= to_write;
	}

	free(page);

	return 0;
}

int ftruncate_vfs(off_t length, struct file *vnode)
{
	if(length < 0)
		return -EINVAL;
	
	if(vnode->f_ino->i_type == VFS_TYPE_DIR)
		return -EISDIR;

	if((size_t) length == vnode->f_ino->i_size)
		return 0;

	rw_lock_write(&vnode->f_ino->i_rwlock);

	int st = 0;
	if(vnode->f_ino->i_fops->ftruncate != NULL)
		st = vnode->f_ino->i_fops->ftruncate(length, vnode);
	else
	{
		st = default_ftruncate(length, vnode);
	}

	rw_unlock_write(&vnode->f_ino->i_rwlock);

	return st;
}

int default_fallocate(int mode, off_t offset, off_t len, struct file *file)
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
	size_t off = offset;
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

int fallocate_vfs(int mode, off_t offset, off_t len, struct file *file)
{
	if(file->f_ino->i_fops->fallocate)
	{
		return file->f_ino->i_fops->fallocate(mode, offset, len, file);
	}
	else
		return default_fallocate(mode, offset, len, file);

	return -EINVAL;
}

int inode_init(struct inode *inode, bool is_cached)
{
	inode->i_refc = 1;
	if(is_cached)
	{
		if(inode_create_vmo(inode) < 0)
		{
			return -ENOMEM;
		}
	}

	rwlock_init(&inode->i_rwlock);

	return 0;
}

struct inode *inode_create(bool is_cached)
{
	struct inode *inode = zalloc(sizeof(*inode));

	if(!inode)
		return NULL;

	if(inode_init(inode, is_cached) < 0)
	{
		free(inode);
		return NULL;
	}

	return inode;
}

void inode_wait_flush(struct inode *ino)
{
	while(ino->i_flags & INODE_FLAG_DIRTYING)
		cpu_relax();
}

void inode_mark_dirty(struct inode *ino)
{
	inode_wait_flush(ino);

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

	__sync_fetch_and_or(&ino->i_flags, INODE_FLAG_DIRTYING);

	int st = sb->flush_inode(ino);

	__sync_fetch_and_and(&ino->i_flags, ~(INODE_FLAG_DIRTYING | INODE_FLAG_DIRTY));

	return st;
}

struct file *inode_to_file(struct inode *ino)
{
	struct file *f = zalloc(sizeof(struct file));
	if(!f)
		return NULL;
	f->f_ino = ino;
	f->f_flags = 0;
	f->f_refcount = 1;
	f->f_seek = 0;
	f->f_dentry = NULL;

	return f;
}
