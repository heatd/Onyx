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

#include <partitions.h>

#include <kernel/compiler.h>
#include <kernel/vmm.h>
#include <kernel/vfs.h>
#include <kernel/process.h>
#include <kernel/pipe.h>
#include <kernel/file.h>

#include <sys/uio.h>

_Bool is_absolute_filename(const char *file)
{
	return *file == '/' ? true : false;
}
vfsnode_t *get_fs_base(const char *file, vfsnode_t *rel_base)
{
	return is_absolute_filename(file) == true ? fs_root : rel_base;
}
vfsnode_t *get_current_directory(void)
{
	return get_current_process()->ctx.cwd;
}
file_desc_t *get_file_description(int fd)
{
	return get_current_process()->ctx.file_desc[fd];
}

static inline int validate_fd(int fd)
{
	ioctx_t *ctx = &get_current_process()->ctx;
	
	if(fd < 0)
		return errno = -EBADF;
	if(fd > UINT16_MAX)
		return errno = -EBADF;
	if(ctx->file_desc[fd] == NULL)
		return errno = -EBADF;
	return 0;
}
/* Enlarges the file descriptor table by UINT8_MAX(255) entries */
int enlarge_file_descriptor_table(process_t *process)
{
	process->ctx.file_desc_entries += UINT8_MAX;
	file_desc_t **table = malloc(process->ctx.file_desc_entries * sizeof(void*));
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
file_desc_t *allocate_file_descriptor_unlocked(int *fd, ioctx_t *ioctx)
{
	while(1)
	{
		for(int i = 0; i < ioctx->file_desc_entries; i++)
		{
			if(ioctx->file_desc[i] == NULL)
			{
				ioctx->file_desc[i] = malloc(sizeof(file_desc_t));
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
	/*if(vmm_check_pointer((void*) buf, count) < 0)
		return errno =-EFAULT; */
	
	ioctx_t *ioctx = &get_current_process()->ctx;
	if(validate_fd(fd) < 0)
	{
		return -EBADF;
	}
	if(!ioctx->file_desc[fd]->flags & O_RDONLY)
	{
		return -EBADF;
	}
	ssize_t size = (ssize_t) read_vfs(ioctx->file_desc[fd]->flags, ioctx->file_desc[fd]->seek,
		count, (char*)buf, ioctx->file_desc[fd]->vfs_node);
	if(size == -1)
	{
		return -errno;
	}
	ioctx->file_desc[fd]->seek += size;
	return size;
}
ssize_t sys_write(int fd, const void *buf, size_t count)
{
	if(vmm_check_pointer((void*) buf, count) < 0)
		return -EFAULT;
	if(validate_fd(fd) < 0)
		return -EBADF;
	if(!get_current_process()->ctx.file_desc[fd]->flags & O_WRONLY)
		return -EBADF;
	size_t written = write_vfs(get_current_process()->ctx.file_desc[fd]->seek, count, (void*) buf, get_current_process()->ctx.file_desc[fd]->vfs_node);

	if(written == (size_t) -1)
		return -errno;
	get_current_process()->ctx.file_desc[fd]->seek += written;
	return written;
}
void handle_open_flags(file_desc_t *fd, int flags)
{
	if(flags & O_APPEND)
		fd->seek = fd->vfs_node->size;
}
static vfsnode_t *try_to_open(vfsnode_t *base, const char *filename, int flags, mode_t mode)
{
	vfsnode_t *ret = open_vfs(base, filename);
	if(!ret && flags & O_CREAT)
		ret = creat_vfs(base, filename, mode);
	return ret;
}
int do_sys_open(const char *filename, int flags, mode_t mode, vfsnode_t *rel)
{
	/* This function does all the open() work, open(2) and openat(2) use this */
	ioctx_t *ioctx = &get_current_process()->ctx;
	vfsnode_t *base = get_fs_base(filename, rel);

	mutex_lock(&ioctx->fdlock);
	int fd_num = -1;

	/* Open/creat the file */
	vfsnode_t *file = try_to_open(base, filename, flags, mode);
	if(!file)
	{
		mutex_unlock(&ioctx->fdlock);
		return -errno;
	}
	/* Allocate a file descriptor and a file description for the file */
	file_desc_t *fd = allocate_file_descriptor_unlocked(&fd_num, ioctx);
	if(!fd)
	{
		mutex_unlock(&ioctx->fdlock);
		close_vfs(file);
		return -errno;
	}
	memset(fd, 0, sizeof(file_desc_t));
	fd->vfs_node = file;
	file->refcount++;
	fd->refcount++;
	fd->seek = 0;
	fd->flags = flags;
	handle_open_flags(fd, flags);
	mutex_unlock(&ioctx->fdlock);
	return fd_num;
}
int sys_open(const char *filename, int flags, mode_t mode)
{
	if(!vmm_is_mapped((char*) filename))
		return -EFAULT;
	/* open(2) does relative opens using the current working directory */
	return do_sys_open(filename, flags, mode, get_current_process()->ctx.cwd);
}
static inline int decrement_fd_refcount(file_desc_t *fd)
{
	/* If there's nobody referencing this file descriptor, close the vfs node and free memory */
	fd->refcount--;
	if(fd->refcount == 0)
	{
		close_vfs(fd->vfs_node);
		fd->vfs_node->refcount--;
		/* TODO: When we implement a VFS hash table, remove this bit of code */
		if(fd->vfs_node->refcount == 0)
		{
			free(fd->vfs_node);
		}
		free(fd);
		return 1;
	}
	return 0;
}
int sys_close(int fd)
{
	ioctx_t *ioctx = &get_current_process()->ctx;	
	if(validate_fd(fd) < 0) 
		return errno =-EBADF;
	/* Decrement the refcount of the file descriptor*/
	decrement_fd_refcount(ioctx->file_desc[fd]);
	
	ioctx->file_desc[fd] = NULL;
	return 0;
}
int sys_dup(int fd)
{
	ioctx_t *ioctx = &get_current_process()->ctx;
	if(validate_fd(fd) < 0)
	{
		return errno =-EBADF;
	}
	mutex_lock(&ioctx->fdlock);
	while(1)
	{
		for(int i = 0; i < ioctx->file_desc_entries; i++)
		{
			if(ioctx->file_desc[i] == NULL)
			{
				ioctx->file_desc[i] = ioctx->file_desc[fd];
				ioctx->file_desc[fd]->vfs_node->refcount++;
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
int sys_dup2(int oldfd, int newfd)
{
	ioctx_t *ioctx = &get_current_process()->ctx;
	if(validate_fd(oldfd) < 0)
		return -EBADF;

	/* TODO: Handle newfd's larger than the number of entries by extending the table */
	if(newfd > ioctx->file_desc_entries)
	{
		return errno =-EBADF;
	}

	if(ioctx->file_desc[newfd])
		sys_close(newfd);
	ioctx->file_desc[newfd] = ioctx->file_desc[oldfd];
	ioctx->file_desc[newfd]->vfs_node->refcount++;
	return newfd;
}
ssize_t sys_readv(int fd, const struct iovec *vec, int veccnt)
{
	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return errno =-EINVAL;

	if(validate_fd(fd) < 0)
		return errno =-EBADF;
	ioctx_t *ctx = &get_current_process()->ctx;
	if(!vec)
		return errno =-EINVAL;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_RDONLY)
		return errno =-EBADF;
	size_t read = 0;
	for(int i = 0; i < veccnt; i++)
	{
		if(vec[i].iov_len == 0)
			continue;
		size_t s = read_vfs(ctx->file_desc[fd]->flags, 
		ctx->file_desc[fd]->seek, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		if(s != vec[i].iov_len)
		{
			read += s;
			ctx->file_desc[fd]->seek += s;
			return read;
		}
		read += s;
		ctx->file_desc[fd]->seek += vec[i].iov_len;
	}
	return read;
}
ssize_t sys_writev(int fd, const struct iovec *vec, int veccnt)
{
	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return errno =-EINVAL;

	size_t wrote = 0;
	if(validate_fd(fd) < 0)
		return -EBADF;
	ioctx_t *ctx = &get_current_process()->ctx;
	if(!vec)
		return errno =-EINVAL;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_WRONLY)
		return errno =-EBADF;
	for(int i = 0; i < veccnt; i++)
	{
		size_t written = write_vfs(ctx->file_desc[fd]->seek, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		if(written == (size_t) -1)
			return -errno;

		wrote += vec[i].iov_len;
		ctx->file_desc[fd]->seek += vec[i].iov_len;
	}
	return wrote;
}
ssize_t sys_preadv(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return errno =-EINVAL;

	if(validate_fd(fd) < 0)
		return errno =-EBADF;
	ioctx_t *ctx = &get_current_process()->ctx;
	if(!vec)
		return errno =-EINVAL;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_RDONLY)
		return errno =-EBADF;
	size_t read = 0;
	for(int i = 0; i < veccnt; i++)
	{
		read_vfs(ctx->file_desc[fd]->flags, 
			offset, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		read += vec[i].iov_len;
		offset += vec[i].iov_len;
	}
	return read;
}
ssize_t sys_pwritev(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
	if(veccnt == 0) return 0;

	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return -EFAULT;
	
	if(validate_fd(fd) < 0)
		return -EBADF;
	
	ioctx_t *ctx = &get_current_process()->ctx;
	
	if(!ctx->file_desc[fd]->flags & O_WRONLY)
		return errno =-EBADF;
	size_t wrote = 0;
	for(int i = 0; i < veccnt; i++)
	{
		size_t written = write_vfs(offset, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		if(written == (size_t) -1)
		{
			return -errno;
		}
		wrote += vec[i].iov_len;
		offset += vec[i].iov_len;
	}
	return wrote;
}
int sys_getdents(int fd, struct dirent *dirp, unsigned int count)
{
	if(validate_fd(fd) < 0)
		return errno =-EBADF;
	if(!count)
		return -EINVAL;

	ioctx_t *ctx = &get_current_process()->ctx;
	int read_entries_size = getdents_vfs(count, dirp, ctx->file_desc[fd]->seek, ctx->file_desc[fd]->vfs_node);
	ctx->file_desc[fd]->seek += read_entries_size;
	return read_entries_size;
}
int sys_ioctl(int fd, int request, char *argp)
{
	if(validate_fd(fd) < 0)
		return errno =-EBADF;
	ioctx_t *ctx = &get_current_process()->ctx;
	return ioctl_vfs(request, argp, ctx->file_desc[fd]->vfs_node);
}
int sys_truncate(const char *path, off_t length)
{
	return errno =-ENOSYS;
}
int sys_ftruncate(int fd, off_t length)
{
	if(validate_fd(fd) < 0)
		return errno =-EBADF;
	return errno =-ENOSYS; 
}
off_t sys_lseek(int fd, off_t offset, int whence)
{
	ioctx_t *ioctx = &get_current_process()->ctx;
	if(validate_fd(fd) < 0)
		return -EBADF;
	if(ioctx->file_desc[fd]->vfs_node->type == VFS_TYPE_FIFO)
		return -ESPIPE;

	mutex_lock(&ioctx->file_desc[fd]->seek_lock);
	if(whence == SEEK_CUR)
		ioctx->file_desc[fd]->seek += offset;
	else if(whence == SEEK_SET)
		ioctx->file_desc[fd]->seek = offset;
	else if(whence == SEEK_END)
		ioctx->file_desc[fd]->seek = ioctx->file_desc[fd]->vfs_node->size;
	else
	{
		mutex_unlock(&ioctx->file_desc[fd]->seek_lock);
		return -EINVAL;
	}
	mutex_unlock(&ioctx->file_desc[fd]->seek_lock);
	return ioctx->file_desc[fd]->seek;
}
int sys_mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)
{
	if(!vmm_is_mapped((void*) source))
		return errno =-EINVAL;
	if(!vmm_is_mapped((void*) target))
		return errno =-EINVAL;
	if(!vmm_is_mapped((void*) filesystemtype))
		return errno =-EINVAL;
	/* Find the 'filesystemtype's handler */
	filesystem_mount_t *fs = find_filesystem_handler(filesystemtype);
	if(!fs)
		return errno = -ENODEV;
	/* Get the device name */
	char *dev_name = strdup(source);
	if(!dev_name)
		return errno = -ENOMEM;
	dev_name[strlen(dev_name)-1] = '\0';
	block_device_t *block = blkdev_search((const char *) dev_name);
	int part_index = source[strlen(source)-1] - '1';

	uint64_t lba = partition_find(part_index, block, fs);
	vfsnode_t *node = NULL;
	int ret = 0;
	if(!(node = fs->handler(lba, block)))
	{
		perror("");
		ret = -1;
		goto exit;
	}
	char *str = strdup(target);
	mount_fs(node, str);
exit:
	free(dev_name);
	return ret;
}
int sys_isatty(int fd)
{
	if(validate_fd(fd) < 0)
		return errno =-EBADF;
	ioctx_t *ioctx = &get_current_process()->ctx;
	if(ioctx->file_desc[fd]->vfs_node->type & VFS_TYPE_CHAR_DEVICE)
		return 1;
	else
		return errno =-ENOTTY;
}
int sys_pipe(int pipefd[2])
{
	if(vmm_check_pointer(pipefd, sizeof(int) * 2) < 0)
		return errno = -EFAULT;

	ioctx_t *ioctx = &get_current_process()->ctx;
	/* Find 2 free file descriptors */
	int wrfd = find_free_fd(0);

	if(wrfd < 0)
		return errno = -EMFILE;
	/* and allocate each of them */
	ioctx->file_desc[wrfd] = malloc(sizeof(file_desc_t));
	if(!ioctx->file_desc[wrfd])
		return errno = -ENOMEM;

	int rdfd = find_free_fd(0);
	
	if(rdfd < 0)
		return errno = -EMFILE;
	ioctx->file_desc[rdfd] = malloc(sizeof(file_desc_t));
	if(!ioctx->file_desc[rdfd])
	{
		free(ioctx->file_desc[wrfd]);
		ioctx->file_desc[wrfd] = NULL;
		return errno = -ENOMEM;
	}
	
	memset(ioctx->file_desc[rdfd], 0, sizeof(file_desc_t));
	memset(ioctx->file_desc[wrfd], 0, sizeof(file_desc_t));
	/* Create the pipe */

	ioctx->file_desc[wrfd]->vfs_node = pipe_create();
	if(!ioctx->file_desc[wrfd]->vfs_node)
	{
		free(ioctx->file_desc[wrfd]);
		ioctx->file_desc[wrfd] = NULL;
		free(ioctx->file_desc[rdfd]);
		ioctx->file_desc[rdfd] = NULL;

		return errno = -ENOMEM;
	}
	ioctx->file_desc[rdfd]->vfs_node = ioctx->file_desc[wrfd]->vfs_node;
	ioctx->file_desc[rdfd]->flags = O_RDONLY;
	ioctx->file_desc[wrfd]->flags = O_WRONLY;

	pipefd[0] = rdfd;
	pipefd[1] = wrfd;

	return 0;
}
int do_dupfd(int fd, int fdbase)
{
	int new_fd = find_free_fd(fdbase);
	ioctx_t *ioctx = &get_current_process()->ctx;
	ioctx->file_desc[fdbase] = ioctx->file_desc[fd];
	ioctx->file_desc[fdbase]->refcount++;
	return new_fd;
}
int sys_fcntl(int fd, int cmd, unsigned long arg)
{
	if(validate_fd(fd) < 0)
		return -EBADF;
	switch(cmd)
	{
		case F_DUPFD:
		{
			int new = do_dupfd(fd, (int) arg);
			return new;
		}
		case F_DUPFD_CLOEXEC:
		{
			int new = do_dupfd(fd, (int) arg);
			get_file_description(new)->flags |= O_CLOEXEC;
			return new;
		}
		case F_GETFD:
		{
			return get_file_description(fd)->flags;
		}
		case F_SETFD:
		{
			get_file_description(fd)->flags = (int) arg;
			return 0;
		}
		default:
			return -EINVAL;
	}
	return 0;
}
int do_sys_stat(const char *pathname, struct stat *buf, int flags, vfsnode_t *rel)
{
	vfsnode_t *base = get_fs_base(pathname, rel);
	vfsnode_t *stat_node = open_vfs(base, pathname);
	if(!stat_node)
		return -errno; /* Don't set errno, as we don't know if it was actually a ENOENT */
	stat_vfs(buf, stat_node);
	close_vfs(stat_node);
	return 0;
}
int sys_stat(const char *pathname, struct stat *buf)
{
	if(!vmm_is_mapped((void*) pathname))
		return errno = -EFAULT;
	if(vmm_check_pointer(buf, sizeof(struct stat)) < 0)
		return errno = -EFAULT;
	return do_sys_stat(pathname, buf, 0, get_current_directory());
}
int sys_fstat(int fd, struct stat *buf)
{
	if(vmm_check_pointer(buf, sizeof(struct stat)) < 0)
		return errno = -EFAULT;
	if(validate_fd(fd) < 0)
		return errno = -EBADF;
	stat_vfs(buf, get_current_process()->ctx.file_desc[fd]->vfs_node);
	return 0;
}
int sys_chdir(const char *path)
{
	if(!vmm_is_mapped((void*) path))
		return errno = -EFAULT;
	vfsnode_t *base = get_fs_base(path, get_current_directory());
	vfsnode_t *dir = open_vfs(base, path);
	if(!dir)
		return -ENOENT;
	if(!(dir->type & VFS_TYPE_DIR))
		return -ENOTDIR;
	get_current_process()->ctx.cwd = dir;
	return 0;
}
int sys_fchdir(int fildes)
{
	if(validate_fd(fildes) < 0)
		return errno = -EBADF;
	vfsnode_t *node = get_current_process()->ctx.file_desc[fildes]->vfs_node;
	if(!(node->type & VFS_TYPE_DIR))
		return -ENOTDIR;

	get_current_process()->ctx.cwd = node;
	return 0;
}
int sys_getcwd(char *path, size_t size)
{
	if(size == 0 && path != NULL)
		return -EINVAL;
	if(vmm_check_pointer(path, size) < 0)
		return -EFAULT;
	if(!get_current_process()->ctx.cwd)
		return -ENOENT;
	vfsnode_t *vnode = get_current_process()->ctx.cwd;

	if(strlen(vnode->name) + 1 > size)
		return -ERANGE;
	strncpy(path, vnode->name, size);
	
	return 0;
}
int sys_openat(int dirfd, const char *path, int flags, mode_t mode)
{
	if(!vmm_is_mapped((void*) path))
		return -EFAULT;
	vfsnode_t *dir;
	if(validate_fd(dirfd) < 0 && dirfd != AT_FDCWD)
		return -EBADF;
	if(dirfd != AT_FDCWD)
		dir = get_file_description(dirfd)->vfs_node;
	else
		dir = get_current_process()->ctx.cwd;
	if(!(dir->type & VFS_TYPE_DIR))
		return -ENOTDIR;
	return do_sys_open(path, flags, mode, dir);
}
int sys_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags)
{
	if(!vmm_is_mapped((void*) pathname))
		return errno = -EFAULT;
	if(vmm_check_pointer(buf, sizeof(struct stat)) < 0)
		return errno = -EFAULT;
	vfsnode_t *dir;
	if(validate_fd(dirfd) < 0 && dirfd != AT_FDCWD)
		return -EBADF;
	if(dirfd != AT_FDCWD)
		dir = get_file_description(dirfd)->vfs_node;
	else
		dir = get_current_process()->ctx.cwd;
	if(!(dir->type & VFS_TYPE_DIR))
		return -ENOTDIR;
	return do_sys_stat(pathname, buf, flags, dir);
}
int sys_fmount(int fd, const char *path)
{
	if(validate_fd(fd) < 0)
		return -EBADF;
	if(!vmm_is_mapped((void*) path))
		return errno = -EFAULT;
	return mount_fs(get_file_description(fd)->vfs_node, path);
}
void file_do_cloexec(ioctx_t *ctx)
{
	mutex_lock(&ctx->fdlock);
	file_desc_t **fd = ctx->file_desc;
	for(int i = 0; i < ctx->file_desc_entries; i++)
	{
		if(!fd[i])
			continue;
		if(fd[i]->flags & O_CLOEXEC)
		{
			/* Close the file */
			decrement_fd_refcount(fd[i]);
			fd[i] = NULL;
		}
	}
	mutex_unlock(&ctx->fdlock);
}
