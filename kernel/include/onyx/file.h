/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_FILE_H
#define _KERNEL_FILE_H

#include <fcntl.h>

#include <onyx/vfs.h>
#include <onyx/panic.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ioctx;

void file_do_cloexec(struct ioctx *ctx);
int open_with_vnode(struct file *node, int flags);
struct file *get_file_description(int fd);
void fd_get(struct file *fd);
void fd_put(struct file *fd);
int allocate_file_descriptor_table(struct process *process);
int copy_file_descriptors(struct process *process, struct ioctx *ctx);

#define OPEN_FLAGS_ACCESS_MODE(flags)	(flags & 0x3)

static inline unsigned int open_to_file_access_flags(int open_flgs)
{
	unsigned int last_two_bits = OPEN_FLAGS_ACCESS_MODE(open_flgs);
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

bool fd_may_access(struct file *f, unsigned int access);

#ifdef __cplusplus
}
#endif
#endif
