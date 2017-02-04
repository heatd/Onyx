/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

#include <kernel/dev.h>
#include <kernel/majorminor.h>

static struct char_dev
{
	dev_t major;
	int subdevs;
	char name[64];
	struct minor_device *list;
} *major_devices[MAJOR_DEVICE_HASHTABLE];

static inline int major_to_hash(dev_t major)
{
	return major % MAJOR_DEVICE_HASHTABLE;
} 
unsigned int __allocate_dynamic_major()
{
	for(unsigned int i = 1; i < MAJOR_DEVICE_HASHTABLE; i++)
	{
		if(!major_devices[i])
		{
			return i;
		}
	}
	int subdev_min = major_devices[1]->subdevs;
	unsigned int best_major = 1;
	for(unsigned int i = 1; i < MAJOR_DEVICE_HASHTABLE; i++)
	{
		if(major_devices[i]->subdevs < subdev_min)
		{
			subdev_min = major_devices[i]->subdevs;
			best_major = i;
		}
	}
	return best_major;
}
struct minor_device *dev_register(unsigned int major, unsigned int first_minor)
{
	struct minor_device *c = NULL;
	
	/* If major == 0, create a dynamic major number */
	if(major == 0)
	{
		major = __allocate_dynamic_major();
	}

	if(!major_devices[major])
	{
		major_devices[major] = malloc(sizeof(struct char_dev));
		if(!major_devices[major])
			return NULL;
		memset(major_devices[major], 0, sizeof(struct char_dev));
		major_devices[major]->major = major;
		major_devices[major]->subdevs = 1;
		c = malloc(sizeof(struct minor_device));
		if(!c)
		{
			free(major_devices[major]);
			major_devices[major] = NULL;
			return NULL;
		}
		memset(c, 0, sizeof(struct minor_device));

		c->next = NULL;
		c->majorminor = MKDEV(major, first_minor);
		
		major_devices[major]->list = c;
		return c;
	}
	else
	{
		c = major_devices[major_to_hash(major)]->list;
		for(; c->next; c = c->next)
		{
			if(MINOR(c->majorminor) == first_minor)
			{
				first_minor++;
			}
		}
	}

	c->next = malloc(sizeof(struct minor_device));
	if(!c->next)
		return NULL;
	memset(c->next, 0, sizeof(struct minor_device));

	major_devices[major_to_hash(major)]->subdevs++;
	c->next->majorminor = MKDEV(major, first_minor);
	c->next->next = NULL;

	return c->next;
}
void dev_unregister(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);

	if(!major_devices[major])
		return;
	
	if(MINOR(major_devices[major]->list->majorminor) == minor)
	{
		major_devices[major]->subdevs--;
		free(major_devices[major]->list);
		major_devices[major]->list = major_devices[major]->list->next;

		if(major_devices[major]->subdevs == 0)
		{
			free(major_devices[major]);
			major_devices[major] = NULL;
		}
		return;
	}
	for(struct minor_device *c = major_devices[major]->list; c->next; c = c->next)
	{
		if(MINOR(c->next->majorminor) == minor)
		{
			free(c->next);
			c->next = c->next->next;
			return;
		}
	}
}
struct minor_device *dev_find(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);
	
	if(!major_devices[major])
		return NULL;

	for(struct minor_device *c = major_devices[major]->list; c; c = c->next)
	{
		if(MINOR(c->majorminor) == minor)
		{
			return c;
		}
	}
	return NULL;
}