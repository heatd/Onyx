/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/dev.h>
#include <onyx/panic.h>
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
    scoped_lock g{bus_list_lock};

    list_add_tail(&bus->bus_list_node, &bus_list);

    bus->bus_sysfs.perms = 0644 | S_IFDIR;

    sysfs_add(&bus->bus_sysfs, &buses_obj);
}

void bus_add_device(struct bus *bus, struct device *device)
{
    scoped_lock g{bus->bus_lock};

    assert(bus != NULL);
    assert(device != NULL);

    device->bus = bus;

    list_add_tail(&device->device_list_node, &bus->device_list_head);

    device->device_sysfs.perms = 0644 | S_IFDIR;

    sysfs_add(&device->device_sysfs, &bus->bus_sysfs);
}

struct device *bus_find_device(struct bus *bus, const char *devname)
{
    assert(bus);
    assert(devname);

    scoped_lock g{bus->bus_lock};

    list_for_every (&bus->device_list_head)
    {
        device *dev = list_head_cpp<device>::self_from_list_head(l);
        if (!strcmp(dev->name, devname))
        {
            spin_unlock(&bus->bus_lock);
            return dev;
        }
    }

    return NULL;
}

void driver_shutdown(struct driver *drv, struct device *d)
{
    if (drv->shutdown)
        drv->shutdown(d);
}

void driver_suspend(struct driver *drv, struct device *d)
{
    if (drv->suspend)
        drv->suspend(d);
}

void driver_resume(struct driver *drv, struct device *d)
{
    if (drv->resume)
        drv->resume(d);
}

void device_shutdown(struct device *dev)
{
    assert(dev);
    if (dev->driver_)
    {
        driver_shutdown(dev->driver_, dev);
    }

    // if(dev->bus->shutdown) dev->bus->shutdown(dev);
}

void device_suspend(struct device *dev)
{
    assert(dev);
    if (dev->driver_)
    {
        driver_suspend(dev->driver_, dev);
    }

    // if(dev->bus->suspend) dev->bus->suspend(dev);
}

void device_resume(struct device *dev)
{
    assert(dev);
    if (dev->driver_)
    {
        driver_resume(dev->driver_, dev);
    }

    // if(dev->bus->resume) dev->bus->resume(dev);
}

void bus_shutdown(struct bus *bus)
{
    assert(bus);
    scoped_lock g{bus->bus_lock};

    list_for_every (&bus->device_list_head)
    {
        auto dev = list_head_cpp<device>::self_from_list_head(l);
        device_shutdown(dev);
    }
}

void bus_shutdown_every(void)
{
    scoped_lock g{bus_list_lock};

    list_for_every (&bus_list)
    {
        struct bus *bus = list_head_cpp<struct bus>::self_from_list_head(l);
        bus_shutdown(bus);
        if (bus->shutdown_bus)
            bus->shutdown_bus(bus);
    }
}

void bus_suspend(struct bus *bus)
{
    assert(bus);

    scoped_lock g{bus->bus_lock};

    list_for_every (&bus->device_list_head)
    {
        struct device *dev = list_head_cpp<device>::self_from_list_head(l);
        device_suspend(dev);
    }
}

void bus_resume(struct bus *bus)
{
    assert(bus);

    scoped_lock g{bus->bus_lock};

    list_for_every (&bus->device_list_head)
    {
        struct device *dev = list_head_cpp<device>::self_from_list_head(l);
        device_resume(dev);
    }
}

void bus_suspend_every(void)
{
    scoped_lock g{bus_list_lock};

    list_for_every (&bus_list)
    {
        struct bus *bus = list_head_cpp<struct bus>::self_from_list_head(l);
        bus_suspend(bus);
    }
}

void bus_resume_every(void)
{
    scoped_lock g{bus_list_lock};

    list_for_every (&bus_list)
    {
        struct bus *bus = list_head_cpp<struct bus>::self_from_list_head(l);
        bus_resume(bus);
    }
}

void bus_unregister(struct bus *bus)
{
    scoped_lock g{bus_list_lock};

    // TODO: Have a bus type list
    list_remove(&bus->bus_list_node);
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
    dev->driver_ = driver;
    __atomic_add_fetch(&driver->ref, 1, __ATOMIC_ACQUIRE);

    scoped_lock g{driver->device_list_lock};
    if (extrusive_list_add(&driver->devices, dev) < 0)
        panic("Failed to register device\n");
}

void driver_deregister_device(struct driver *driver, struct device *dev)
{
    scoped_lock g{driver->device_list_lock};
    extrusive_list_remove(&driver->devices, dev);
    dev->driver_ = nullptr;
}

int dev_printk(struct device *dev, const char *log_lvl, const char *fmt, ...)
{
    int err = 0;
    va_list va;

    va_start(va, fmt);
    err = printk_loglvl_generic("%s%s %s: ", &va, fmt, log_lvl,
                                dev->driver_ ? dev->driver_->name : dev->bus->name, dev->name);
    va_end(va);
    return err;
}

int bus_printk(struct device *dev, const char *log_lvl, const char *fmt, ...)
{
    int err = 0;
    va_list va;

    va_start(va, fmt);
    err = printk_loglvl_generic("%s%s %s: ", &va, fmt, log_lvl, dev->bus->name, dev->name);
    va_end(va);
    return err;
}
