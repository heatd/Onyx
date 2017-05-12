/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_DEV_H
#define _KERNEL_DEV_H
#include <stdint.h>

#include <sys/types.h>

#include <kernel/majorminor.h>
#include <kernel/vfs.h>

#define MAJOR_DEVICE_HASHTABLE 256

struct minor_device
{
	struct minor_device *next;
	dev_t majorminor;
	struct file_ops *fops;
};

unsigned int __allocate_dynamic_major(void);
struct minor_device *dev_register(unsigned int major, unsigned int first_minor);
void dev_unregister(dev_t dev);
struct minor_device *dev_find(dev_t dev);

int devfs_init(void);
void null_init(void);
void zero_init(void);
extern vfsnode_t *slashdev;

#endif