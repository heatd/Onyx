/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#include <kernel/dev.h>

static spinlock_t bus_list_lock;
static struct bus *bus_list = NULL;
void bus_register(struct bus *bus)
{
	acquire_spinlock(&bus_list_lock);
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
	release_spinlock(&bus_list_lock);
}
void bus_add_device(struct bus *bus, struct device *device)
{
	acquire_spinlock(&bus->bus_lock);
	assert(bus);
	assert(device);

	if(!bus->devs)
		bus->devs = device;
	else
	{
		struct device *d = bus->devs;
		while(d->next) d = d->next;

		d->next = device;
		device->prev = d;
		device->bus = bus;
	}
	release_spinlock(&bus->bus_lock);
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
void device_shutdown(struct device *dev)
{
	assert(dev);
	if(dev->shutdown) dev->shutdown(dev);
}
void device_suspend(struct device *dev)
{
	assert(dev);
	if(dev->suspend) dev->suspend(dev);
}
void device_resume(struct device *dev)
{
	assert(dev);
	if(dev->resume) dev->resume(dev);
}
void bus_shutdown(struct bus *bus)
{
	assert(bus);
	acquire_spinlock(&bus->bus_lock);
	for(struct device *dev = bus->devs; dev; dev = dev->next)
	{
		device_shutdown(dev);
	}
	release_spinlock(&bus->bus_lock);
}
void bus_shutdown_every(void)
{
	acquire_spinlock(&bus_list_lock);
	for(struct bus *bus = bus_list; bus; bus = bus->next)
	{
		bus_shutdown(bus);
		if(bus->shutdown) bus->shutdown(bus);
	}
	release_spinlock(&bus_list_lock);
}
void bus_suspend(struct bus *bus)
{
	assert(bus);
	acquire_spinlock(&bus->bus_lock);
	for(struct device *dev = bus->devs; dev; dev = dev->next)
	{
		device_suspend(dev);
	}
	release_spinlock(&bus->bus_lock);
}
void bus_resume(struct bus *bus)
{
	assert(bus);
	acquire_spinlock(&bus->bus_lock);
	for(struct device *dev = bus->devs; dev; dev = dev->next)
	{
		device_resume(dev);
	}
	release_spinlock(&bus->bus_lock);
}
void bus_suspend_every(void)
{
	acquire_spinlock(&bus_list_lock);
	for(struct bus *bus = bus_list; bus; bus = bus->next)
	{
		bus_suspend(bus);
	}
	release_spinlock(&bus_list_lock);
}
void bus_resume_every(void)
{
	acquire_spinlock(&bus_list_lock);
	for(struct bus *bus = bus_list; bus; bus = bus->next)
	{
		bus_resume(bus);
	}
	release_spinlock(&bus_list_lock);
}
void bus_unregister(struct bus *bus)
{
	acquire_spinlock(&bus_list_lock);
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
	release_spinlock(&bus_list_lock);
}
