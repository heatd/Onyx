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

#include <partitions.h>

#include <kernel/compiler.h>
#include <kernel/vmm.h>
#include <kernel/vfs.h>
#include <kernel/process.h>
#include <kernel/pipe.h>

#include <sys/uio.h>

inline int validate_fd(int fd)
{
	if(fd < 0)
		return errno = -EBADF;
	if(fd > UINT16_MAX)
		return errno =-EBADF;
	ioctx_t *ctx = &get_current_process()->ctx;
	if(ctx->file_desc[fd] == NULL)
		return errno =-EBADF;
	return 0;
}
inline int find_free_fd()
{
	ioctx_t *ioctx = &get_current_process()->ctx;
	for(int i = 0; i < UINT16_MAX; i++)
	{
		if(ioctx->file_desc[i] == NULL)
		{
			return i;
		}
	}
	return -EMFILE;
}
ssize_t sys_read(int fd, const void *buf, size_t count)
{
	/*if(vmm_check_pointer((void*) buf, count) < 0)
		return errno =-EFAULT;*/

	ioctx_t *ioctx = &get_current_process()->ctx;
	if( fd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	if(ioctx->file_desc[fd] == NULL)
	{
		return errno =-EBADF;
	}
	if(!ioctx->file_desc[fd]->flags & O_RDONLY)
		return errno =-EBADF;
	ssize_t size = (ssize_t) read_vfs(ioctx->file_desc[fd]->seek, count, (char*)buf, ioctx->file_desc[fd]->vfs_node);
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
	if(validate_fd(fd))
		return -EBADF;
	if(!get_current_process()->ctx.file_desc[fd]->flags & O_WRONLY)
		return -EBADF;
	size_t written = write_vfs(get_current_process()->ctx.file_desc[fd]->seek, count, (void*) buf, get_current_process()->ctx.file_desc[fd]->vfs_node);

	if(written == (size_t) -1)
		return -errno;
	return written;
}
int sys_open(const char *filename, int flags)
{
	ioctx_t *ioctx = &get_current_process()->ctx;
	for(int i = 0; i < UINT16_MAX; i++)
	{
		if(ioctx->file_desc[i] == NULL)
		{
			ioctx->file_desc[i] = malloc(sizeof(file_desc_t));
			if(!ioctx->file_desc[i])
				return errno = -ENOMEM;
			memset(ioctx->file_desc[i], 0, sizeof(file_desc_t));
			ioctx->file_desc[i]->vfs_node = open_vfs(fs_root, filename);
			if(!ioctx->file_desc[i]->vfs_node)
			{
				free(ioctx->file_desc[i]);
				return errno =-ENOENT;
			}
			ioctx->file_desc[i]->vfs_node->refcount++;
			ioctx->file_desc[i]->refcount++;
			ioctx->file_desc[i]->seek = 0;
			ioctx->file_desc[i]->flags = flags;
			return i;
		}
	}
	return errno =-ENFILE;
}
inline int decrement_fd_refcount(file_desc_t *fd)
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
	if(fd > UINT16_MAX) 
	{
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &get_current_process()->ctx;	
	if(ioctx->file_desc[fd] == NULL)
	{
		return errno =-EBADF;
	}
	/* Decrement the refcount of the file descriptor*/
	if(decrement_fd_refcount(ioctx->file_desc[fd]))
	{
		ioctx->file_desc[fd] = NULL;
	}
	return 0;
}
int sys_dup(int fd)
{
	if(fd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &get_current_process()->ctx;
	if(ioctx->file_desc[fd] == NULL)
	{
		return errno =-EBADF;
	}
	for(int i = 0; i < UINT16_MAX; i++)
	{
		if(ioctx->file_desc[i] == NULL)
		{
			ioctx->file_desc[i] = ioctx->file_desc[fd];
			ioctx->file_desc[fd]->vfs_node->refcount++;
			return i;
		}
	}
	return errno =-EMFILE;
}
int sys_dup2(int oldfd, int newfd)
{
	if(oldfd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	if(newfd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &get_current_process()->ctx;
	if(ioctx->file_desc[oldfd] == NULL)
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

	if(validate_fd(fd))
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
		size_t s = read_vfs(ctx->file_desc[fd]->seek, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
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
	if(validate_fd(fd))
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

	if(validate_fd(fd))
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
		read_vfs(offset, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
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
	
	if(validate_fd(fd))
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
	if(validate_fd(fd))
		return errno =-EBADF;
	if(!count)
		return -EINVAL;

	ioctx_t *ctx = &get_current_process()->ctx;
	int read_entries_size = getdents_vfs(count, dirp, ctx->file_desc[fd]->seek, ctx->file_desc[fd]->vfs_node);
	ctx->file_desc[fd]->seek += read_entries_size;
	return read_entries_size;
}
int sys_ioctl(int fd, int request, va_list args)
{
	if(validate_fd(fd))
		return errno =-EBADF;
	ioctx_t *ctx = &get_current_process()->ctx;
	return ioctl_vfs(request, args, ctx->file_desc[fd]->vfs_node);
}
int sys_truncate(const char *path, off_t length)
{
	return errno =-ENOSYS;
}
int sys_ftruncate(int fd, off_t length)
{
	if(validate_fd(fd))
		return errno =-EBADF;
	return errno =-ENOSYS; 
}
off_t sys_lseek(int fd, off_t offset, int whence)
{
	ioctx_t *ioctx = &get_current_process()->ctx;
	if (fd > UINT16_MAX)
		return errno =-EBADF;
	if(ioctx->file_desc[fd] == NULL)
		return errno =-EBADF;
	if(ioctx->file_desc[fd]->vfs_node->type == VFS_TYPE_FIFO)
		return -ESPIPE;
	
	if(whence == SEEK_CUR)
		ioctx->file_desc[fd]->seek += offset;
	else if(whence == SEEK_SET)
		ioctx->file_desc[fd]->seek = offset;
	else if(whence == SEEK_END)
		ioctx->file_desc[fd]->seek = ioctx->file_desc[fd]->vfs_node->size;
	else
		return errno =-EINVAL;

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
	if(validate_fd(fd))
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
	int wrfd = find_free_fd();

	if(wrfd < 0)
		return errno = -EMFILE;
	/* and allocate each of them */
	ioctx->file_desc[wrfd] = malloc(sizeof(file_desc_t));
	if(!ioctx->file_desc[wrfd])
		return errno = -ENOMEM;

	int rdfd = find_free_fd();
	
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
int sys_fcntl(int fd, int cmd, ...)
{
	printk("%s: not implemented yet\n", __func__);
	return 0;
}
int sys_stat(const char *pathname, struct stat *buf)
{
	if(!vmm_is_mapped((void*) pathname))
		return errno = -EFAULT;
	if(vmm_check_pointer(buf, sizeof(struct stat)) < 0)
		return errno = -EFAULT;
	
	vfsnode_t *stat_node = open_vfs(fs_root, pathname);
	if(!stat_node)
		return -errno; /* Don't set errno, as we don't know if it was actually a ENOENT */
	stat_vfs(buf, stat_node);
	close_vfs(stat_node);
	return -errno;
}
int sys_fstat(int fd, struct stat *buf)
{
	if(vmm_check_pointer(buf, sizeof(struct stat)) < 0)
		return errno = -EFAULT;
	if(validate_fd(fd))
		return errno = -EBADF;
	stat_vfs(buf, get_current_process()->ctx.file_desc[fd]->vfs_node);
	return -errno;
}
