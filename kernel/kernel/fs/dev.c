/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <sys/types.h>

#include <onyx/dev.h>
#include <onyx/majorminor.h>
#include <onyx/compiler.h>
#include <onyx/panic.h>
#include <onyx/tmpfs.h>

static struct dev *devices[MAJOR_DEVICE_HASHTABLE];

tmpfs_filesystem_t *tmpfs_root;

static inline int major_to_hash(dev_t major)
{
	return major;
}

unsigned int __allocate_dynamic_major(void)
{
	for(unsigned int i = 1; i < MAJOR_DEVICE_HASHTABLE; i++)
	{
		if(!devices[i])
		{
			return i;
		}
	}

	return (unsigned int) -1;
}

struct dev *dev_register(unsigned int major, unsigned int minor, char *name)
{
	struct dev *c = NULL;
	struct dev *dev = NULL;
	
	/* If major == 0, create a dynamic major number */
	if(major == 0)
	{
		major = __allocate_dynamic_major();
		if(major == (unsigned int) -1)
			return NULL;
	}

	/* Create a new dev and set it up */
	dev = zalloc(sizeof(struct dev));
	if(!dev)
		return NULL;
	
	dev->majorminor = MKDEV(major, minor);
	dev->name = strdup(name);
	if(!dev->name)
	{
		free(dev);
		return NULL;
	}

	if(!devices[major])
	{
		devices[major] = dev;
	}
	else
	{
		c = devices[major_to_hash(major)];
		for(; c->next; c = c->next)
		{
			if(MINOR(c->majorminor) == minor)
			{
				free(dev);
				return errno = EEXIST, NULL;
			}
		}
		c->next = dev;
	}

	return dev;
}

void dev_unregister(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);

	struct dev *d = devices[major];

	if(d->majorminor == dev)
	{
		devices[major] = d->next;
		free(d);
		return;
	}

	for(; d->next; d = d->next)
	{
		if(d->next->majorminor == minor)
		{
			struct dev *found = d->next;
			d->next = found->next;
			free(found);
			return;
		}
	}
}

struct dev *dev_find(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);
	
	if(!devices[major])
		return NULL;

	for(struct dev *c = devices[major]; c; c = c->next)
	{
		if(MINOR(c->majorminor) == minor)
		{
			return c;
		}
	}

	return NULL;
}

void devfs_init(void)
{
	/* Mount tmpfs on /dev */
	assert(tmpfs_mount("/dev") == 0);

	struct inode *dev = open_vfs(get_fs_root(), "/dev");

	assert(dev != NULL);

	tmpfs_root = tmpfs_get_root(dev);
	tmpfs_root->root->name = strdup("/dev");
}

int device_show(struct dev *d)
{
	tmpfs_file_t *file = tmpfs_create_file(tmpfs_root->root, d->name);

	if(!file)
		return -1;
	d->file = file;

	file->st_uid = 0;
	file->st_gid = 0;
	file->rdev = d->majorminor;
	file->type = d->is_block ? TMPFS_FILE_TYPE_BLOCK : TMPFS_FILE_TYPE_CHAR;

	return 0;
}
