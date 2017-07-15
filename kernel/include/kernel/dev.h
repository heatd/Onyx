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
#include <kernel/spinlock.h>

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

struct bus;
struct device;

struct driver
{
	const char *name;
	struct bus *bus;
	struct device *device;
	_Atomic int ref;
};
struct device
{
	const char *name;
	struct bus *bus;
	struct driver *driver;
	int (*suspend)(struct device *);
	int (*resume)(struct device *);

	int (*shutdown)(struct device *);
	struct device *prev, *next;
};
struct bus
{
	const char *name; 	/* Name of the bus */
	spinlock_t bus_lock;
	struct device *devs;	/* List of every device connected to this bus */

	int (*shutdown)(struct bus *);
	struct bus *prev, *next;
};

/* bus_register - Register a bus */
void bus_register(struct bus *bus);
/* bus_unregister - Unregister a bus */
void bus_unregister(struct bus *bus);
/* bus_add_device - Add a device to a bus */
void bus_add_device(struct bus *bus, struct device *device);
/* bus_find_device - Find a device on the bus */
struct device *bus_find_device(struct bus *bus, const char *devname);
/* bus_shutdown - Shutdown every device on the bus */
void bus_shutdown(struct bus *bus);
#endif
