/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <kernel/vmm.h>
#include <kernel/vfs.h>
#include <kernel/process.h>
#include <kernel/pipe.h>

#include <sys/uio.h>

inline int validate_fd(int fd)
{
	if(fd > UINT16_MAX)
		return errno =-EBADF;
	ioctx_t *ctx = &current_process->ctx;
	if(ctx->file_desc[fd] == NULL)
		return errno =-EBADF;
	return 0;
}
inline int find_free_fd()
{
	ioctx_t *ioctx = &current_process->ctx;
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
	if(vmm_check_pointer((void*) buf, count) < 0)
		return errno =-EINVAL;

	ioctx_t *ioctx = &current_process->ctx;
	if( fd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	if(ioctx->file_desc[fd] == NULL)
	{
		return errno =-EBADF;
	}
	if(!buf)
		return errno =-EINVAL;
	if(!ioctx->file_desc[fd]->flags & O_RDONLY)
		return errno =-EBADF;
	ssize_t size = read_vfs(ioctx->file_desc[fd]->seek, count, (char*)buf, ioctx->file_desc[fd]->vfs_node);
	ioctx->file_desc[fd]->seek += size;
	return size;
}
ssize_t sys_write(int fd, const void *buf, size_t count)
{
	if(vmm_check_pointer((void*) buf, count) < 0)
		return errno =-EINVAL;

	if(validate_fd(fd))
		return errno =-EBADF;
	if(!current_process->ctx.file_desc[fd]->flags & O_WRONLY)
		return errno =-EROFS;
	write_vfs(current_process->ctx.file_desc[fd]->seek, count, (void*) buf, current_process->ctx.file_desc[fd]->vfs_node);
	return count;
}
int sys_open(const char *filename, int flags)
{
	ioctx_t *ioctx = &current_process->ctx;
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
			ioctx->file_desc[i]->seek = 0;
			ioctx->file_desc[i]->flags = flags;
			return i;
		}
	}
	return errno =-ENFILE;
}
int sys_close(int fd)
{
	if(fd > UINT16_MAX) 
	{
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &current_process->ctx;	
	if(ioctx->file_desc[fd] == NULL)
	{
		return errno =-EBADF;
	}
	close_vfs(ioctx->file_desc[fd]->vfs_node);
	ioctx->file_desc[fd]->vfs_node->refcount--;
	if(ioctx->file_desc[fd]->vfs_node->refcount == 0)
	{
		free(ioctx->file_desc[fd]->vfs_node);
		free(ioctx->file_desc[fd]);
	}
	return 0;
}
int sys_dup(int fd)
{
	if(fd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &current_process->ctx;
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
	ioctx_t *ioctx = &current_process->ctx;
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
	ioctx_t *ctx = &current_process->ctx;
	if(!vec)
		return errno =-EINVAL;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_RDONLY)
		return errno =-EBADF;
	size_t read = 0;
	for(int i = 0; i < veccnt; i++)
	{
		size_t s = read_vfs(ctx->file_desc[fd]->seek, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		if(s != vec[i].iov_len)
		{
			return read;
		}
		read += vec[i].iov_len;
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
	ioctx_t *ctx = &current_process->ctx;
	if(!vec)
		return errno =-EINVAL;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_WRONLY)
		return errno =-EROFS;
	for(int i = 0; i < veccnt; i++)
	{
		write_vfs(ctx->file_desc[fd]->seek, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
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
	ioctx_t *ctx = &current_process->ctx;
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
	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return errno =-EINVAL;

	if(validate_fd(fd))
		return -1;
	ioctx_t *ctx = &current_process->ctx;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_WRONLY)
		return errno =-EROFS;
	size_t wrote = 0;
	for(int i = 0; i < veccnt; i++)
	{
		write_vfs(offset, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		wrote += vec[i].iov_len;
		offset += vec[i].iov_len;
	}
	return wrote;
}
int sys_getdents(int fd, struct dirent *dirp, unsigned int count)
{
	if(vmm_check_pointer((void*) dirp, sizeof(struct dirent) * count) < 0)
		return errno =-EINVAL;
	if(validate_fd(fd))
		return errno =-EBADF;
	if(!count)
		return 0;
	ioctx_t *ctx = &current_process->ctx;
	int read_entries_size = getdents_vfs(count, dirp, ctx->file_desc[fd]->vfs_node);
	return read_entries_size;
}
int sys_ioctl(int fd, int request, va_list args)
{
	if(validate_fd(fd))
		return errno =-EBADF;
	ioctx_t *ctx = &current_process->ctx;
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
	if (fd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd] == NULL)
	{
		return errno =-EBADF;
	}
	if(whence == SEEK_CUR)
		ioctx->file_desc[fd]->seek += offset;
	else if(whence == SEEK_SET)
		ioctx->file_desc[fd]->seek = offset;
	else if(whence == SEEK_END)
		ioctx->file_desc[fd]->seek = ioctx->file_desc[fd]->vfs_node->size;
	else
	{
		return errno =-EINVAL;
	}
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
	if(!vmm_is_mapped((void*) data))
		return errno =-EINVAL;

	return 0;
}
int sys_isatty(int fd)
{
	if(validate_fd(fd))
		return errno =-EBADF;
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd]->vfs_node->type & VFS_TYPE_CHAR_DEVICE)
		return 1;
	else
		return errno =-ENOTTY;
}
int sys_pipe(int pipefd[2])
{
	if(vmm_check_pointer(pipefd, sizeof(int) * 2) < 0)
		return errno = -EFAULT;

	ioctx_t *ioctx = &current_process->ctx;
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

	pipefd[0] = rdfd;
	pipefd[1] = wrfd;

	return 0;
}
