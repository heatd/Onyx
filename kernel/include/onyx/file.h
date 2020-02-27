/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_FILE_H
#define _KERNEL_FILE_H

#include <fcntl.h>

#include <onyx/ioctx.h>
#include <onyx/vfs.h>
#include <onyx/panic.h>

#ifdef __cplusplus
extern "C" {
#endif

void file_do_cloexec(ioctx_t *ctx);
int open_with_vnode(struct inode *node, int flags);
struct file *get_file_description(int fd);
void fd_get(struct file *fd);
void fd_put(struct file *fd);

static inline unsigned int open_to_file_access_flags(int open_flgs)
{
	unsigned int last_two_bits = (open_flgs & 0x3);
	if(last_two_bits == O_RDONLY)
		return FILE_ACCESS_READ;
	else if(last_two_bits == O_RDWR)
		return FILE_ACCESS_READ | FILE_ACCESS_WRITE;
	else if(last_two_bits == O_WRONLY)
		return FILE_ACCESS_WRITE;
	else
	{
		panic("Unsanitized open flags");
	}
}

#ifdef __cplusplus
}
#endif
#endif
