/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_FILE_H
#define _KERNEL_FILE_H
#include <kernel/ioctx.h>
#include <kernel/vfs.h>

#ifdef __cplusplus
extern "C" {
#endif
void file_do_cloexec(ioctx_t *ctx);
int open_with_vnode(vfsnode_t *node, int flags);
#ifdef __cplusplus
}
#endif
#endif
