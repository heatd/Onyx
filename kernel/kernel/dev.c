/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>

#include <onyx/atomic.h>
#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/sysfs.h>

static struct spinlock bus_list_lock;
static struct bus *bus_list = NULL;

void bus_register(struct bus *bus)
{
	spin_lock(&bus_list_lock);
	assert(bus);
	if(!bus_list)
		bus_list = bus;
	else
	{
		struct bus *b = bus_list;
		while(b->next) b = b->next;

		b->next = bus;
		bus->prev = b;
	}
	spin_unlock(&bus_list_lock);
}

void bus_add_device(struct bus *bus, struct device *device)
{
	spin_lock(&bus->bus_lock);
	assert(bus);
	assert(device);
	device->bus = bus;
	if(!bus->devs)
		bus->devs = device;
	else
	{
		struct device *d = bus->devs;
		while(d->next) d = d->next;

		d->next = device;
		device->prev = d;
	}
	spin_unlock(&bus->bus_lock);
}

struct device *bus_find_device(struct bus *bus, const char *devname)
{
	assert(bus);
	assert(devname);
	if(!bus->devs)
		return NULL;
	for(struct device *dev = bus->devs; dev; dev = dev->next)
	{
		if(!strcmp(dev->name, devname))
			return dev;
	}
	return NULL;
}

void driver_shutdown(struct driver *drv, struct device *d)
{
	if(drv->shutdown)
		drv->shutdown(d);
}

void driver_suspend(struct driver *drv, struct device *d)
{
	if(drv->suspend)
		drv->suspend(d);
}

void driver_resume(struct driver *drv, struct device *d)
{
	if(drv->resume)
		drv->resume(d);
}

void device_shutdown(struct device *dev)
{
	assert(dev);
	if(dev->driver)
	{
		driver_shutdown(dev->driver, dev);
	}

	if(dev->bus->shutdown) dev->bus->shutdown(dev);
}

void device_suspend(struct device *dev)
{
	assert(dev);
	if(dev->driver)
	{
		driver_suspend(dev->driver, dev);
	}

	if(dev->bus->suspend) dev->bus->suspend(dev);
}

void device_resume(struct device *dev)
{
	assert(dev);
	if(dev->driver)
	{
		driver_resume(dev->driver, dev);
	}

	if(dev->bus->resume) dev->bus->resume(dev);
}

void bus_shutdown(struct bus *bus)
{
	assert(bus);
	spin_lock(&bus->bus_lock);
	for(struct device *dev = bus->devs; dev; dev = dev->next)
	{
		device_shutdown(dev);
	}
	spin_unlock(&bus->bus_lock);
}

void bus_shutdown_every(void)
{
	spin_lock(&bus_list_lock);
	for(struct bus *bus = bus_list; bus; bus = bus->next)
	{
		bus_shutdown(bus);
		if(bus->shutdown_bus) bus->shutdown_bus(bus);
	}
	spin_unlock(&bus_list_lock);
}

void bus_suspend(struct bus *bus)
{
	assert(bus);
	spin_lock(&bus->bus_lock);
	for(struct device *dev = bus->devs; dev; dev = dev->next)
	{
		device_suspend(dev);
	}
	spin_unlock(&bus->bus_lock);
}

void bus_resume(struct bus *bus)
{
	assert(bus);
	spin_lock(&bus->bus_lock);
	for(struct device *dev = bus->devs; dev; dev = dev->next)
	{
		device_resume(dev);
	}
	spin_unlock(&bus->bus_lock);
}

void bus_suspend_every(void)
{
	spin_lock(&bus_list_lock);
	for(struct bus *bus = bus_list; bus; bus = bus->next)
	{
		bus_suspend(bus);
	}
	spin_unlock(&bus_list_lock);
}

void bus_resume_every(void)
{
	spin_lock(&bus_list_lock);
	for(struct bus *bus = bus_list; bus; bus = bus->next)
	{
		bus_resume(bus);
	}
	spin_unlock(&bus_list_lock);
}

void bus_unregister(struct bus *bus)
{
	spin_lock(&bus_list_lock);
	if(bus == bus_list)
	{
		bus_list = bus->next;
		bus_list->prev = NULL;
	}
	else
	{
		bus->prev->next = bus->next;
		bus->next->prev = bus->prev;
	}
	spin_unlock(&bus_list_lock);
}

static void dev_add_files(void)
{
	for(struct bus *b = bus_list; b != NULL; b = b->next)
	{
		assert(sysfs_add_bus(b) != NULL);
		for(struct device *d = b->devs; d != NULL; d = d->next)
		{
			assert(sysfs_add_device(d) != NULL);
		}
	}
}

void dev_create_sysfs(void)
{
	struct inode *root = open_vfs(get_fs_root(), "/sys");
	struct sysfs_file *devices = NULL;
	struct sysfs_file *buses = NULL;
	assert((devices = sysfs_create_dir("devices", 0666, root)) != NULL);
	assert((buses = sysfs_create_dir("buses", 0666, root)) != NULL);

	dev_add_files();
}

void driver_register_device(struct driver *driver, struct device *dev)
{
	dev->driver = driver;
	atomic_inc(&driver->ref, 1);
	
	spin_lock(&driver->device_list_lock);
	if(extrusive_list_add(&driver->devices, dev) < 0)
		panic("Failed to register device\n");

	spin_unlock(&driver->device_list_lock);
}

void driver_deregister_device(struct driver *driver, struct device *dev)
{
	spin_lock(&driver->device_list_lock);

	extrusive_list_remove(&driver->devices, dev);

	spin_unlock(&driver->device_list_lock);
}
