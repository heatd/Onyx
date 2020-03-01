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
static struct list_head bus_list = LIST_HEAD_INIT(bus_list);

static struct sysfs_object devices_obj;
static struct sysfs_object buses_obj;

int bus_init(struct bus *bus)
{
	return sysfs_object_init(bus->name, &bus->bus_sysfs);
}

int device_init(struct device *dev)
{
	return sysfs_object_init(dev->name, &dev->device_sysfs);
}

void bus_register(struct bus *bus)
{
	spin_lock(&bus_list_lock);

	list_add_tail(&bus->bus_list_node, &bus_list);

	spin_unlock(&bus_list_lock);

	bus->bus_sysfs.perms = 0644 | S_IFDIR;

	sysfs_add(&bus->bus_sysfs, &buses_obj);
}

void bus_add_device(struct bus *bus, struct device *device)
{
	spin_lock(&bus->bus_lock);
	
	assert(bus != NULL);
	assert(device != NULL);
	
	device->bus = bus;
	
	list_add_tail(&device->device_list_node, &bus->device_list_head);

	spin_unlock(&bus->bus_lock);

	device->device_sysfs.perms = 0644 | S_IFDIR;

	sysfs_add(&device->device_sysfs, &bus->bus_sysfs);
}

struct device *bus_find_device(struct bus *bus, const char *devname)
{
	assert(bus);
	assert(devname);

	spin_lock(&bus->bus_lock);

	list_for_every(&bus->device_list_head)
	{
		struct device *dev = container_of(l, struct device, device_list_node);
		if(!strcmp(dev->name, devname))
		{
			spin_unlock(&bus->bus_lock);
			return dev;
		}
	}

	spin_unlock(&bus->bus_lock);
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
	
	list_for_every(&bus->device_list_head)
	{
		struct device *dev = container_of(l, struct device, device_list_node);
		device_shutdown(dev);
	}

	spin_unlock(&bus->bus_lock);
}

void bus_shutdown_every(void)
{
	spin_lock(&bus_list_lock);
	
	list_for_every(&bus_list)
	{
		struct bus *bus = container_of(l, struct bus, bus_list_node);
		bus_shutdown(bus);
		if(bus->shutdown_bus) bus->shutdown_bus(bus);
	}

	spin_unlock(&bus_list_lock);
}

void bus_suspend(struct bus *bus)
{
	assert(bus);

	spin_lock(&bus->bus_lock);

	list_for_every(&bus->device_list_head)
	{
		struct device *dev = container_of(l, struct device, device_list_node);
		device_suspend(dev);
	}

	spin_unlock(&bus->bus_lock);
}

void bus_resume(struct bus *bus)
{
	assert(bus);
	
	spin_lock(&bus->bus_lock);
	
	list_for_every(&bus->device_list_head)
	{
		struct device *dev = container_of(l, struct device, device_list_node);
		device_resume(dev);
	}

	spin_unlock(&bus->bus_lock);
}

void bus_suspend_every(void)
{
	spin_lock(&bus_list_lock);
	
	list_for_every(&bus_list)
	{
		struct bus *bus = container_of(l, struct bus, bus_list_node);
		bus_suspend(bus);
	}

	spin_unlock(&bus_list_lock);
}

void bus_resume_every(void)
{
	spin_lock(&bus_list_lock);
	
	list_for_every(&bus_list)
	{
		struct bus *bus = container_of(l, struct bus, bus_list_node);
		bus_resume(bus);
	}

	spin_unlock(&bus_list_lock);
}

void bus_unregister(struct bus *bus)
{
	spin_lock(&bus_list_lock);
	
	list_remove(&bus->bus_list_node);

	spin_unlock(&bus_list_lock);
}

#if 0
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

#endif

void dev_create_sysfs(void)
{
	assert(sysfs_init_and_add("devices", &devices_obj, NULL) == 0);
	devices_obj.perms = 0644 | S_IFDIR;
	assert(sysfs_init_and_add("bus", &buses_obj, NULL) == 0);
	buses_obj.perms = 0644 | S_IFDIR;
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
