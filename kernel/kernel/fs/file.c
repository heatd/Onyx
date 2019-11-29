/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include <partitions.h>

#include <onyx/compiler.h>
#include <onyx/vm.h>
#include <onyx/vfs.h>
#include <onyx/process.h>
#include <onyx/pipe.h>
#include <onyx/file.h>
#include <onyx/atomic.h>
#include <onyx/user.h>
#include <onyx/panic.h>

#include <sys/uio.h>

bool is_absolute_filename(const char *file)
{
	return *file == '/' ? true : false;
}

struct inode *get_fs_base(const char *file, struct inode *rel_base)
{
	return is_absolute_filename(file) == true ? get_fs_root() : rel_base;
}

struct inode *get_current_directory(void)
{
	return get_current_process()->ctx.cwd;
}

void fd_get(struct file *fd)
{
	__sync_add_and_fetch(&fd->refcount, 1);
}

void fd_put(struct file *fd)
{
	if(__sync_sub_and_fetch(&fd->refcount, 1) == 0)
	{
		close_vfs(fd->vfs_node);
		free(fd);
	}
}

static bool validate_fd_number(int fd, ioctx_t *ctx)
{
	if(fd >= ctx->file_desc_entries)
	{
		return false;
	}

	if(fd < 0)
	{
		return false;
	}
	
	if(ctx->file_desc[fd] == NULL)
	{
		return false;
	}

	return true;
}

struct file *__get_file_description(int fd, struct process *p)
{
	ioctx_t *ctx = &p->ctx;

	mutex_lock(&ctx->fdlock);

	if(!validate_fd_number(fd, ctx))
		goto badfd;

	struct file *f = ctx->file_desc[fd];
	fd_get(f);

	mutex_unlock(&ctx->fdlock);

	return f;
badfd:
	mutex_unlock(&ctx->fdlock);
	return errno = EBADF, NULL;
}

int __file_close_unlocked(int fd, struct process *p)
{
	ioctx_t *ctx = &p->ctx;

	if(!validate_fd_number(fd, ctx))
		goto badfd;

	struct file *f = ctx->file_desc[fd];
	
	/* Decrement the ref count and set the entry to NULL */
	/* TODO: Shrink the fd table? */
	fd_put(f);

	ctx->file_desc[fd] = NULL;

	
	return 0;
badfd:
	return -EBADF;
}

int __file_close(int fd, struct process *p)
{
	ioctx_t *ctx = &p->ctx;

	mutex_lock(&ctx->fdlock);

	int ret = __file_close_unlocked(fd, p);

	mutex_unlock(&ctx->fdlock);

	return ret;
}

int file_close(int fd)
{
	return __file_close(fd, get_current_process());
}

struct file *get_file_description(int fd)
{
	return __get_file_description(fd, get_current_process());
}

/* Enlarges the file descriptor table by UINT8_MAX(255) entries */
int enlarge_file_descriptor_table(struct process *process)
{
	process->ctx.file_desc_entries += UINT8_MAX;
	struct file **table = malloc(process->ctx.file_desc_entries * sizeof(void*));
	if(!table)
		return -1;
	memcpy(table, process->ctx.file_desc, (process->ctx.file_desc_entries - UINT8_MAX) * sizeof(void*));
	free(process->ctx.file_desc);
	process->ctx.file_desc = table;
	return 0;
}

static inline int find_free_fd(int fdbase)
{
	ioctx_t *ioctx = &get_current_process()->ctx;
	mutex_lock(&ioctx->fdlock);
	while(1)
	{
		for(int i = fdbase; i < ioctx->file_desc_entries; i++)
		{
			if(ioctx->file_desc[i] == NULL)
			{
				mutex_unlock(&ioctx->fdlock);
				return i;
			}
		}
		if(enlarge_file_descriptor_table(get_current_process()) < 0)
		{
			mutex_unlock(&ioctx->fdlock);
			return -ENOMEM;
		}
	}
}

struct file *allocate_file_descriptor_unlocked(int *fd, ioctx_t *ioctx)
{
	while(1)
	{
		for(int i = 0; i < ioctx->file_desc_entries; i++)
		{
			if(ioctx->file_desc[i] == NULL)
			{
				ioctx->file_desc[i] = malloc(sizeof(struct file));
				if(!ioctx->file_desc[i])
					return NULL;
				*fd = i;
				return ioctx->file_desc[i];
			}
		}
		if(enlarge_file_descriptor_table(get_current_process()) < 0)
		{
			return NULL;
		}
	}
}

ssize_t sys_read(int fd, const void *buf, size_t count)
{	
	/*if(vm_check_pointer((void*) buf, count) < 0)
		return errno =-EFAULT; */
	
	struct file *f = get_file_description(fd);
	if(!f)
		goto error;

	if(!f->flags & O_RDONLY)
	{
		errno = EBADF;
		goto error;
	}

	ssize_t size = (ssize_t) read_vfs(f->flags, f->seek,
		count, (char*) buf, f->vfs_node);
	if(size == -1)
	{
		goto error;
	}

	/* TODO: Seek adjustments are required to be atomic */
	__sync_add_and_fetch(&f->seek, size);
	fd_put(f);

	return size;
error:
	if(f) fd_put(f);
	return -errno;
}

ssize_t sys_write(int fd, const void *buf, size_t count)
{
	if(vm_check_pointer((void*) buf, count) < 0)
		return -EFAULT;
	
	struct file *f = get_file_description(fd);
	if(!f)
		goto error;

	if(!f->flags & O_WRONLY)
	{
		errno = EBADF;
		goto error;
	}
	
	size_t written = write_vfs(f->seek,
				   count, (void*) buf, 
				   f->vfs_node);

	if(written == (size_t) -1)
		goto error;

	__sync_add_and_fetch(&f->seek, written);

	fd_put(f);
	return written;
error:
	if(f) fd_put(f);
	return -errno;
}

void handle_open_flags(struct file *fd, int flags)
{
	if(flags & O_APPEND)
		fd->seek = fd->vfs_node->i_size;
}

static struct inode *try_to_open(struct inode *base, const char *filename, int flags, mode_t mode)
{
	struct inode *ret = open_vfs(base, filename);
	if(!ret && flags & O_CREAT)
		ret = creat_vfs(base, filename, mode);
	return ret;
}

int do_sys_open(const char *filename, int flags, mode_t mode, struct inode *rel)
{
	//printk("Open(%s)\n", filename);
	/* This function does all the open() work, open(2) and openat(2) use this */
	ioctx_t *ioctx = &get_current_process()->ctx;
	struct inode *base = get_fs_base(filename, rel);

	mutex_lock(&ioctx->fdlock);
	int fd_num = -1;

	/* Open/creat the file */
	struct inode *file = try_to_open(base, filename, flags, mode);
	if(!file)
	{
		mutex_unlock(&ioctx->fdlock);
		return -errno;
	}
	/* Allocate a file descriptor and a file description for the file */
	struct file *fd = allocate_file_descriptor_unlocked(&fd_num, ioctx);
	if(!fd)
	{
		mutex_unlock(&ioctx->fdlock);
		close_vfs(file);
		return -errno;
	}
	
	memset(fd, 0, sizeof(struct file));
	
	fd->vfs_node = file;
	object_ref(&file->i_object);
	fd->refcount = 1;
	fd->seek = 0;

	fd->flags = flags;

	handle_open_flags(fd, flags);
	mutex_unlock(&ioctx->fdlock);
	return fd_num;
}

int sys_open(const char *ufilename, int flags, mode_t mode)
{
	const char *filename = strcpy_from_user(ufilename);
	if(!filename)
		return -errno;
	/* open(2) does relative opens using the current working directory */
	int fd = do_sys_open(filename, flags, mode, get_current_process()->ctx.cwd);
	free((char *) filename);
	return fd;
}

int sys_close(int fd)
{
	return file_close(fd);
}

int sys_dup(int fd)
{
	ioctx_t *ioctx = &get_current_process()->ctx;
	
	struct file *f = get_file_description(fd);
	if(!f)
		return -errno;

	mutex_lock(&ioctx->fdlock);
	while(true)
	{
		/* TODO: This is not optimized. And it's quite ugly code too */
		for(int i = 0; i < ioctx->file_desc_entries; i++)
		{
			if(ioctx->file_desc[i] == NULL)
			{
				ioctx->file_desc[i] = f;
				mutex_unlock(&ioctx->fdlock);
				fd_put(f);
				return i;
			}
		}

		if(enlarge_file_descriptor_table(get_current_process()) < 0)
		{
			mutex_unlock(&ioctx->fdlock);
			fd_put(f);
			return -ENOMEM;
		}
	}
}

int sys_dup2(int oldfd, int newfd)
{
	ioctx_t *ioctx = &get_current_process()->ctx;

	struct file *f = get_file_description(oldfd);
	if(!f)
		return -errno;

	mutex_lock(&ioctx->fdlock);
	/* TODO: Handle newfd's larger than the number of entries by extending the table */
	if(newfd > ioctx->file_desc_entries)
	{
		panic("TODO");
		fd_put(f);
		mutex_unlock(&ioctx->fdlock);
		return -EBADF;
	}

	if(ioctx->file_desc[newfd])
		__file_close_unlocked(newfd, get_current_process());

	ioctx->file_desc[newfd] = ioctx->file_desc[oldfd];

	/* Note: To avoid fd_get/fd_put, we use the ref we get from
	 * get_file_description as the ref for newfd. Therefore, we don't
	 * fd_get and fd_put().
	*/

	mutex_unlock(&ioctx->fdlock);

	return newfd;
}

ssize_t sys_readv(int fd, const struct iovec *vec, int veccnt)
{
	size_t read = 0;

	struct file *f = get_file_description(fd);
	if(!f)
		goto error;

	if(!vec)
	{
		errno = EINVAL;
		goto error;
	}

	if(veccnt == 0)
	{
		read = 0;
		goto out;
	}

	if(!f->flags & O_RDONLY)
	{
		errno = EBADF;
		goto error;
	}

	for(int i = 0; i < veccnt; i++)
	{
		struct iovec v;
		if(copy_from_user(&v, vec++, sizeof(struct iovec)) < 0)
		{
			errno = EFAULT;
			goto error;
		}
	
		if(v.iov_len == 0)
			continue;
		size_t was_read = read_vfs(f->flags, 
			f->seek, v.iov_len, v.iov_base,
			f->vfs_node);

		read += was_read;
		f->seek += was_read;

		if(was_read != v.iov_len)
		{
			goto out;
		}
	}

out:
	fd_put(f);

	return read;
error:
	if(f)	fd_put(f);
	return -errno;
}

ssize_t sys_writev(int fd, const struct iovec *vec, int veccnt)
{
	size_t written = 0;

	struct file *f = get_file_description(fd);
	if(!f)
		goto error;

	if(!vec)
	{
		errno = EINVAL;
		goto error;
	}

	if(veccnt == 0)
	{
		written = 0;
		goto out;
	}

	if(!f->flags & O_WRONLY)
	{
		errno = EBADF;
		goto error;
	}

	for(int i = 0; i < veccnt; i++)
	{
		struct iovec v;
		if(copy_from_user(&v, vec++, sizeof(struct iovec)) < 0)
		{
			errno = EFAULT;
			goto error;
		}
	
		if(v.iov_len == 0)
			continue;
		size_t was_written = write_vfs(f->seek,
			v.iov_len, v.iov_base,f->vfs_node);

		written += was_written;
		f->seek += was_written;

		if(was_written != v.iov_len)
		{
			goto out;
		}
	}

out:
	fd_put(f);

	return written;
error:
	if(f)	fd_put(f);
	return -errno;
}

ssize_t sys_preadv(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
		size_t read = 0;

	struct file *f = get_file_description(fd);
	if(!f)
		goto error;

	if(!vec)
	{
		errno = EINVAL;
		goto error;
	}

	if(veccnt == 0)
	{
		read = 0;
		goto out;
	}

	if(!f->flags & O_RDONLY)
	{
		errno = EBADF;
		goto error;
	}

	for(int i = 0; i < veccnt; i++)
	{
		struct iovec v;
		if(copy_from_user(&v, vec++, sizeof(struct iovec)) < 0)
		{
			errno = EFAULT;
			goto error;
		}
	
		if(v.iov_len == 0)
			continue;
		size_t was_read = read_vfs(f->flags, 
			offset, v.iov_len, v.iov_base,
			f->vfs_node);

		read += was_read;
		offset += was_read;

		if(was_read != v.iov_len)
		{
			goto out;
		}
	}

out:
	fd_put(f);

	return read;
error:
	if(f)	fd_put(f);
	return -errno;
}

ssize_t sys_pwritev(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
	size_t written = 0;

	struct file *f = get_file_description(fd);
	if(!f)
		goto error;

	if(!vec)
	{
		errno = EINVAL;
		goto error;
	}

	if(veccnt == 0)
	{
		written = 0;
		goto out;
	}

	if(!f->flags & O_WRONLY)
	{
		errno = EBADF;
		goto error;
	}

	for(int i = 0; i < veccnt; i++)
	{
		struct iovec v;
		if(copy_from_user(&v, vec++, sizeof(struct iovec)) < 0)
		{
			errno = EFAULT;
			goto error;
		}
	
		if(v.iov_len == 0)
			continue;
		size_t was_written = write_vfs(offset,
			v.iov_len, v.iov_base,f->vfs_node);

		written += was_written;
		offset += was_written;

		if(was_written != v.iov_len)
		{
			goto out;
		}
	}

out:
	fd_put(f);

	return written;
error:
	if(f)	fd_put(f);
	return -errno;
}

unsigned int putdir(struct dirent *buf, struct dirent *ubuf, unsigned int count);

int sys_getdents(int fd, struct dirent *dirp, unsigned int count)
{
	int ret = 0;
	if(!count)
		return -EINVAL;

	struct file *f = get_file_description(fd);
	if(!f)
	{
		ret = -errno;
		goto out;
	}

	struct getdents_ret ret_buf = {0};
	ret = getdents_vfs(count, putdir, dirp, f->seek,
		&ret_buf, f->vfs_node);
	if(ret < 0)
	{
		ret = -errno;
		goto out;
	}

	f->seek = ret_buf.new_off;

	ret = ret_buf.read;
out:
	if(f)	fd_put(f);
	return ret;
}

int sys_ioctl(int fd, int request, char *argp)
{
	struct file *f = get_file_description(fd);
	if(!f)
	{
		return -errno;
	}

	int ret = ioctl_vfs(request, argp, f->vfs_node);

	fd_put(f);
	return ret;
}

int sys_truncate(const char *path, off_t length)
{
	return -ENOSYS;
}

int sys_ftruncate(int fd, off_t length)
{
	struct file *f = get_file_description(fd);
	if(!f)
	{
		return -errno;
	}
	
	int ret = ftruncate_vfs(length, f->vfs_node);

	fd_put(f);
	return ret;
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
	/* TODO: Fix O_APPEND behavior */
	off_t ret = 0;
	struct file *f = get_file_description(fd);
	if(!f)
		return -errno;

	/* TODO: Add a way for inodes to tell they don't support seeking */
	if(f->vfs_node->i_type == VFS_TYPE_FIFO)
	{
		ret = -ESPIPE;
		goto out;
	}
	
	if(whence == SEEK_CUR)
		ret = __sync_add_and_fetch(&f->seek, offset);
	else if(whence == SEEK_SET)
		ret = f->seek = offset;
	else if(whence == SEEK_END)
		ret = f->seek = f->vfs_node->i_size + offset;
	else
	{
		ret = -EINVAL;
	}

out:
	fd_put(f);
	return ret;
}

int sys_mount(const char *usource, const char *utarget, const char *ufilesystemtype,
	      unsigned long mountflags, const void *data)
{
	const char *source = NULL;
	const char *target = NULL;
	const char *filesystemtype = NULL;
	char *dev_name = NULL;
	int ret = 0;

	source = strcpy_from_user(usource);
	if(!source)
	{
		ret = -errno;
		goto out;
	}
	 
	target = strcpy_from_user(utarget);
	if(!target)
	{
		ret = -errno;
		goto out;
	}

	filesystemtype = strcpy_from_user(ufilesystemtype);
	if(!filesystemtype)
	{
		ret = -errno;
		goto out;
	}
	/* Find the 'filesystemtype's handler */
	filesystem_mount_t *fs = find_filesystem_handler(filesystemtype);
	if(!fs)
	{
		ret = -ENODEV;
		goto out;
	}

	/* Get the device name */
	dev_name = strdup(source);
	if(!dev_name)
	{
		ret = -ENOMEM;
		goto out;
	}

	dev_name[strlen(dev_name)-1] = '\0';

	block_device_t *block = blkdev_search((const char *) dev_name);
	int part_index = source[strlen(source)-1] - '1';

	uint64_t lba = partition_find(part_index, block, fs);
	struct inode *node = NULL;
	if(!(node = fs->handler(lba, block)))
	{
		perror("");
		ret = -EINVAL;
		goto out;
	}

	char *str = strdup(target);
	mount_fs(node, str);
out:
	if(source)   free((void *) source);
	if(target)   free((void *) target);
	if(filesystemtype) free((void *) filesystemtype);
	if(dev_name) free(dev_name);
	return ret;
}

int sys_isatty(int fd)
{	
	struct file *f = get_file_description(fd);
	if(!f)
		return -errno;

	/* TODO: This doesn't work since it says every chardev is a tty.
	 * Add a way for inodes to say they're ttys
	*/

	int ret = -ENOTTY;
	if(f->vfs_node->i_type & VFS_TYPE_CHAR_DEVICE)
		ret = 1;
	
	fd_put(f);
	return ret;
}

int sys_pipe(int upipefd[2])
{
	int pipefd[2] = {-1, -1};

	ioctx_t *ioctx = &get_current_process()->ctx;
	/* Find 2 free file descriptors */
	int wrfd = find_free_fd(0);

	if(wrfd < 0)
		return errno = -EMFILE;
	/* and allocate each of them */
	ioctx->file_desc[wrfd] = zalloc(sizeof(struct file));
	if(!ioctx->file_desc[wrfd])
		return errno = -ENOMEM;

	int rdfd = find_free_fd(0);
	
	if(rdfd < 0)
		return errno = -EMFILE;
	ioctx->file_desc[rdfd] = zalloc(sizeof(struct file));
	if(!ioctx->file_desc[rdfd])
	{
		free(ioctx->file_desc[wrfd]);
		ioctx->file_desc[wrfd] = NULL;
		return errno = -ENOMEM;
	}

	/* Create the pipe */
	struct inode *read_end, *write_end;

	/* TODO: Free the file descriptor number on failure */
	if(pipe_create(&read_end, &write_end) < 0)
	{
		free(ioctx->file_desc[wrfd]);
		ioctx->file_desc[wrfd] = NULL;
		free(ioctx->file_desc[rdfd]);
		ioctx->file_desc[rdfd] = NULL;

		return errno = -ENOMEM;
	}

	ioctx->file_desc[rdfd]->refcount = 1;
	ioctx->file_desc[wrfd]->refcount = 1;
	ioctx->file_desc[rdfd]->vfs_node = read_end;
	ioctx->file_desc[wrfd]->vfs_node = write_end;

	ioctx->file_desc[rdfd]->flags = O_RDONLY;
	ioctx->file_desc[wrfd]->flags = O_WRONLY;

	pipefd[0] = rdfd;
	pipefd[1] = wrfd;

	if(copy_to_user(upipefd, pipefd, sizeof(int) * 2) < 0)
		return -EFAULT;

	return 0;
}

int do_dupfd(struct file *f, int fdbase)
{
	int new_fd = find_free_fd(fdbase);
	ioctx_t *ioctx = &get_current_process()->ctx;
	ioctx->file_desc[fdbase] = f;
	fd_get(f);

	return new_fd;
}

int sys_fcntl(int fd, int cmd, unsigned long arg)
{
	struct file *f = get_file_description(fd);
	if(!f)
		return -errno;

	int ret = 0;
	switch(cmd)
	{
		case F_DUPFD:
		{
			ret = do_dupfd(f, (int) arg);
			break;
		}

		case F_DUPFD_CLOEXEC:
		{
			ret = do_dupfd(f, (int) arg);
			struct file *new = get_file_description(ret);
			new->flags |= O_CLOEXEC;
			fd_put(new);

			break;
		}

		case F_GETFD:
		{
			ret = f->flags;
			break;
		}

		case F_SETFD:
		{
			f->flags = (int) arg;
			ret = 0;
			break;
		}
		default:
			ret = -EINVAL;
			break;
	}

	fd_put(f);
	return ret;
}

int do_sys_stat(const char *pathname, struct stat *buf, int flags, struct inode *rel)
{
	struct inode *base = get_fs_base(pathname, rel);
	struct inode *stat_node = open_vfs(base, pathname);
	if(!stat_node)
		return -errno; /* Don't set errno, as we don't know if it was actually a ENOENT */

	int st = stat_vfs(buf, stat_node);
	close_vfs(stat_node);
	return st < 0 ? -errno : st;
}

int sys_stat(const char *upathname, struct stat *ubuf)
{
	const char *pathname = strcpy_from_user(upathname);
	if(!pathname)
		return -errno;
	
	struct stat buf = {0};

	int st = do_sys_stat(pathname, &buf, 0, get_current_directory());

	if(copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
	{
		st = -errno;
	}

	free((void *) pathname);
	return st;
}

int sys_fstat(int fd, struct stat *ubuf)
{
	int ret = 0;

	struct file *f = get_file_description(fd);
	if(!f)
	{
		ret = -errno;
		goto out;
	}

	struct stat buf = {0};

	if(stat_vfs(&buf, f->vfs_node) < 0)
	{
		ret = -errno;
		goto out;
	}

	if(copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
	{
		ret = -EFAULT;
		goto out;
	}

out:
	if(f)	fd_put(f);
	return ret;
}

int sys_chdir(const char *upath)
{
	const char *path = strcpy_from_user(upath);
	if(!path)
		return -errno;

	int st = 0;
	struct inode *base = get_fs_base(path, get_current_directory());
	struct inode *dir = open_vfs(base, path);
	if(!dir)
	{
		st = -ENOENT;
		goto out;
	}

	if(!(dir->i_type & VFS_TYPE_DIR))
	{
		st = -ENOTDIR;
		close_vfs(dir);
		goto out;
	}

	get_current_process()->ctx.cwd = dir;
	get_current_process()->ctx.name = path;
	path = NULL;

out:
	if(path)	free((void *) path);
	return st;
}

int sys_fchdir(int fildes)
{
	struct file *f = get_file_description(fildes);
	if(!f)
		return -errno;

	struct inode *node = f->vfs_node;
	if(!(node->i_type & VFS_TYPE_DIR))
	{
		fd_put(f);
		return -ENOTDIR;
	}

	get_current_process()->ctx.cwd = node;
	get_current_process()->ctx.name = "TODO";

	fd_put(f);

	return 0;
}

int sys_getcwd(char *path, size_t size)
{
	if(size == 0 && path != NULL)
		return -EINVAL;

	struct process *current = get_current_process();

	if(!current->ctx.cwd)
		return -ENOENT;

	if(strlen(current->ctx.name) + 1 > size)
		return -ERANGE;

	if(copy_to_user(path, current->ctx.name, strlen(current->ctx.name) + 1) < 0)
		return -errno;
	return 0;
}

int sys_openat(int dirfd, const char *upath, int flags, mode_t mode)
{
	struct inode *dir;
	struct file *dirfd_desc = NULL;

	if(dirfd != AT_FDCWD)
	{
		dirfd_desc = get_file_description(dirfd);
		if(!dirfd_desc)
			return -errno;
		dir = dirfd_desc->vfs_node;
	}
	else
		dir = get_current_process()->ctx.cwd;

	/* TODO: Possible CWD race condition? */

	if(!(dir->i_type & VFS_TYPE_DIR))
	{
		if(dirfd_desc) fd_put(dirfd_desc);
		return -ENOTDIR;
	}
	
	const char *path = strcpy_from_user(upath);
	if(!path)
	{
		if(dirfd_desc) fd_put(dirfd_desc);
		return -errno;
	}
	int fd = do_sys_open(path, flags, mode, dir);

	free((char *) path);
	if(dirfd_desc) fd_put(dirfd_desc);

	return fd;
}

int sys_fstatat(int dirfd, const char *upathname, struct stat *ubuf, int flags)
{
	const char *pathname = strcpy_from_user(upathname);
	if(!pathname)
		return -errno;
	struct stat buf = {0};
	struct inode *dir;
	int st = 0;
	struct file *dirfd_desc = NULL;
	
	if(dirfd != AT_FDCWD)
	{
		dirfd_desc = get_file_description(dirfd);
		if(!dirfd_desc)
		{
			st = -errno;
			goto out;
		}

		dir = dirfd_desc->vfs_node;
	}
	else
		dir = get_current_process()->ctx.cwd;

	if(!(dir->i_type & VFS_TYPE_DIR))
	{
		st = -ENOTDIR;
		goto out;
	}

	st = do_sys_stat(pathname, &buf, flags, dir);

	if(copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
	{
		st = -errno;
		goto out;
	}
out:
	if(dirfd_desc)	fd_put(dirfd_desc);
	free((void *) pathname);
	return st;
}

int sys_fmount(int fd, const char *upath)
{
	struct file *f = get_file_description(fd);
	if(!f)
		return -errno;

	const char *path = strcpy_from_user(upath);
	if(!path)
	{
		fd_put(f);
		return -errno;
	}

	int st = mount_fs(f->vfs_node, path);

	free((void *) path);
	fd_put(f);
	return st;
}

void file_do_cloexec(ioctx_t *ctx)
{
	mutex_lock(&ctx->fdlock);
	struct file **fd = ctx->file_desc;
	
	for(int i = 0; i < ctx->file_desc_entries; i++)
	{
		if(!fd[i])
			continue;
		if(fd[i]->flags & O_CLOEXEC)
		{
			/* Close the file */
			fd_put(fd[i]);
			fd[i] = NULL;
		}
	}
	mutex_unlock(&ctx->fdlock);
}

int open_with_vnode(struct inode *node, int flags)
{
	/* This function does all the open() work, open(2) and openat(2) use this */
	ioctx_t *ioctx = &get_current_process()->ctx;

	mutex_lock(&ioctx->fdlock);
	int fd_num = -1;
	/* Allocate a file descriptor and a file description for the file */
	struct file *fd = allocate_file_descriptor_unlocked(&fd_num, ioctx);
	if(!fd)
	{
		mutex_unlock(&ioctx->fdlock);
		return -errno;
	}

	memset(fd, 0, sizeof(struct file));
	fd->vfs_node = node;
	
	object_ref(&node->i_object);

	fd->refcount = 1;
	fd->seek = 0;
	fd->flags = flags;
	handle_open_flags(fd, flags);
	mutex_unlock(&ioctx->fdlock);
	return fd_num;
}

ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags,
	struct sockaddr *addr, socklen_t addrlen)
{
	struct file *desc = get_file_description(sockfd);
	if(!desc)
		return -errno;

	if(desc->vfs_node->i_type != VFS_TYPE_UNIX_SOCK)
	{
		fd_put(desc);
		return -ENOTSOCK;
	}

	ssize_t ret = sendto_vfs(buf, len, flags, addr, addrlen, desc->vfs_node);

	fd_put(desc);
	return ret;
}

int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct file *desc = get_file_description(sockfd);
	if(!desc)
		return -errno;

	if(desc->vfs_node->i_type != VFS_TYPE_UNIX_SOCK)
	{
		fd_put(desc);
		return -ENOTSOCK;
	}

	int ret = connect_vfs(addr, addrlen, desc->vfs_node);

	fd_put(desc);
	return ret;
}

int sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct file *desc = get_file_description(sockfd);
	if(!desc)
		return -errno;

	if(desc->vfs_node->i_type != VFS_TYPE_UNIX_SOCK)
	{
		fd_put(desc);
		return -ENOTSOCK;
	}

	int ret = bind_vfs(addr, addrlen, desc->vfs_node);

	fd_put(desc);
	return ret;
}

ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags,
struct sockaddr *src_addr, socklen_t *addrlen)
{
	struct file *desc = get_file_description(sockfd);
	if(!desc)
		return -errno;

	if(desc->vfs_node->i_type != VFS_TYPE_UNIX_SOCK)
	{
		fd_put(desc);
		return -ENOTSOCK;
	}

	ssize_t ret = recvfrom_vfs(buf, len, flags, src_addr, addrlen, desc->vfs_node);
	
	fd_put(desc);
	return ret;
}

struct file *create_file_description(struct inode *inode, off_t seek)
{
	struct file *fd = zalloc(sizeof(*fd));
	if(!fd)
		return NULL;
	fd->vfs_node = inode;
	fd->seek = seek;
	fd->refcount = 1;
	
	object_ref(&inode->i_object);

	return fd;
}

void close_file_description(struct file *fd)
{
	object_unref(&fd->vfs_node->i_object);
	
	if(--fd->refcount == 0)
		free(fd);
}

/* Simple stub sys_access */
int sys_access(const char *path, int amode)
{
	const char *p = strcpy_from_user(path);
	if(!p)
		return -errno;

	struct inode *ino = open_vfs(get_fs_base(p, get_current_directory()), p);
	if(!ino)
		return -ENOENT;
	
	return 0;
}