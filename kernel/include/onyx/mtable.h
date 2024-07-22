/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_MTABLE_H
#define _KERNEL_MTABLE_H

#include <onyx/types.h>

typedef struct
{
    ino_t ino;
    dev_t dev;
    struct file *rootfs;
} mountpoint_t;

struct file *mtable_lookup(struct file *mountpoint);
int mtable_mount(struct file *mountpoint, struct file *rootfs);

#endif
