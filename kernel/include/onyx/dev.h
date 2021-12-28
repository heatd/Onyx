/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_DEV_H
#define _KERNEL_DEV_H
#include <stdint.h>
#include <stdbool.h>

#include <sys/types.h>

#include <onyx/majorminor.h>
#include <onyx/vfs.h>
#include <onyx/spinlock.h>
#include <onyx/list.h>
#include <onyx/sysfs.h>
#include <onyx/list.h>

#define MAJOR_DEVICE_HASHTABLE 255

struct dev
{
	struct dev *next;
	dev_t majorminor;
	struct file_ops fops;
	char *name;
	void *priv;
	bool is_block;
	struct inode *file;
};

unsigned int __allocate_dynamic_major(void);
struct dev *dev_register(unsigned int major, unsigned int minor, const char *name);
void dev_unregister(dev_t dev);
struct dev *dev_find(dev_t dev);

#define DEVICE_NO_PATH			""

int device_create_dir(const char *path);
int device_mknod(struct dev *d, const char *path, const char *name, mode_t mode);
int device_show(struct dev *d, const char *path, mode_t mode);

struct bus;
struct device;

struct driver
{
	const char *name;
	struct bus *bus;
	struct spinlock device_list_lock;
	struct extrusive_list_head devices;
	unsigned long ref;
	void *devids;

	int (*probe)(device *dev);
	void (*shutdown)(device *dev);
	void (*resume)(device *dev);
	void (*suspend)(device *dev);

	list_head_cpp<driver> bus_type_node;
};

struct device
{
	device *parent;
	const char *name;
	struct bus *bus;
	driver *driver_;
	sysfs_object device_sysfs;
	void *priv;

	extrusive_list_head children;
	list_head_cpp<device> device_list_node;

	device(const char *name, struct bus *bus, device *parent) : parent{parent}, name{name}, bus{bus},
           driver_{nullptr}, device_sysfs{}, priv{}, children{}, device_list_node{this}
	{
	
	}

	virtual int shutdown()
	{
		return 0;
	}

	virtual int resume()
	{
		return 0;
	}

	virtual int suspend()
	{
		return 0;
	}
};

struct bus;

/* bus_init - Initialize a bus structure */
int bus_init(struct bus *bus);

struct bus
{
	/* Name of the bus */
	const char *name;
	spinlock bus_lock;
	/* List of every device connected to this bus */
	list_head device_list_head;
	list_head child_buses;
	sysfs_object bus_sysfs;

	int (*shutdown_bus)(bus *);
	int (*suspend_bus)(bus *);
	int (*resume_bus)(bus *);
	list_head_cpp<bus> bus_list_node;
	list_head_cpp<bus> bus_type_node;
	list_head_cpp<bus> child_buses_node;

	virtual void probe(driver *drv)
	{
		list_for_every(&device_list_head)
		{
			auto dev = list_head_cpp<device>::self_from_list_head(l);
			(void) dev;
			// TODO
		}
	}

	template <typename Callable>
	void for_every_device(Callable cb)
	{
		scoped_lock g{bus_lock};
		list_for_every(&device_list_head)
		{
			auto dev = list_head_cpp<device>::self_from_list_head(l);
			if(!cb(dev))
				return;
		}
	}

	bus(const char *name) : name{name}, bus_lock{}, device_list_head{}, bus_sysfs{},
              shutdown_bus{}, suspend_bus{}, resume_bus{}, bus_list_node{this}, bus_type_node{this},
			  child_buses_node{this}
	{
		INIT_LIST_HEAD(&device_list_head);
		INIT_LIST_HEAD(&child_buses);
		bus_init(this);
	}

	void add_bus(bus *b)
	{
		scoped_lock g{bus_lock};
		list_add_tail(&b->child_buses_node, &child_buses);
	}

	template <typename Callable>
	void for_every_child_bus(Callable cb)
	{
		scoped_lock g{bus_lock};
		list_for_every(&child_buses)
		{
			auto b = list_head_cpp<bus>::self_from_list_head(l);
			if(!cb(b))
				return;
		}
	}
};

/* bus_init - Initialize a device structure */
int device_init(struct device *dev);

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

#endif
