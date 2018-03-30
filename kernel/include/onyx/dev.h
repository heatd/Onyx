/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_DEV_H
#define _KERNEL_DEV_H
#include <stdint.h>

#include <sys/types.h>

#include <onyx/majorminor.h>
#include <onyx/vfs.h>
#include <onyx/spinlock.h>
#include <onyx/list.h>

#define MAJOR_DEVICE_HASHTABLE 256

struct minor_device
{
	struct minor_device *next;
	dev_t majorminor;
	struct file_ops *fops;
	void *ptr; /* Helper pointer */
};

#ifdef __cplusplus
extern "C" {
#endif
unsigned int __allocate_dynamic_major(void);
struct minor_device *dev_register(unsigned int major, unsigned int first_minor);
void dev_unregister(dev_t dev);
struct minor_device *dev_find(dev_t dev);

int devfs_init(void);
void null_init(void);
void zero_init(void);
extern struct inode *slashdev;

struct bus;
struct device;

struct driver
{
	const char *name;
	struct bus *bus;
	spinlock_t device_list_lock;
	struct list_head devices;
	unsigned long ref;

	void (*shutdown)(struct device *dev);
	void (*resume)(struct device *dev);
	void (*suspend)(struct device *dev);
};

struct device
{
	struct device *parent;
	const char *name;
	struct bus *bus;
	struct driver *driver;

	struct list_head children;
	struct device *prev, *next;
};

struct bus
{
	const char *name; 	/* Name of the bus */
	spinlock_t bus_lock;
	struct device *devs;	/* List of every device connected to this bus */

	int (*shutdown)(struct device *);
	int (*resume)(struct device *);
	int (*suspend)(struct device *);

	int (*shutdown_bus)(struct bus *);
	int (*suspend_bus)(struct bus *);
	int (*resume_bus)(struct bus *);
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
/* bus_shutdown_every - Shutdown every bus */
void bus_shutdown_every(void);
/* bus_suspend_every - Suspend every bus */
void bus_suspend_every(void);

void dev_create_sysfs(void);

void driver_register_device(struct driver *driver, struct device *dev);

void driver_deregister_device(struct driver *driver, struct device *dev);

#ifdef __cplusplus
}
#endif
#endif
