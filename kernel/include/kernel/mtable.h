/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_MTABLE_H
#define _KERNEL_MTABLE_H

#include <sys/types.h>

typedef struct
{
	ino_t ino;
	dev_t dev;
	vfsnode_t *rootfs;
} mountpoint_t;
vfsnode_t *mtable_lookup(vfsnode_t *mountpoint);
int mtable_mount(vfsnode_t *mountpoint, vfsnode_t *rootfs);

#endif
