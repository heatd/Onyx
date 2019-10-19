/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_FILE_H
#define _KERNEL_FILE_H
#include <onyx/ioctx.h>
#include <onyx/vfs.h>

#ifdef __cplusplus
extern "C" {
#endif

void file_do_cloexec(ioctx_t *ctx);
int open_with_vnode(struct inode *node, int flags);
struct file *get_file_description(int fd);
void fd_get(struct file *fd);
void fd_put(struct file *fd);

#ifdef __cplusplus
}
#endif
#endif
