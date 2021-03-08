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
#include <onyx/vfs.h>
#include <onyx/init.h>

static struct dev *devices[MAJOR_DEVICE_HASHTABLE];

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

struct dev *dev_register(unsigned int major, unsigned int minor, const char *name)
{
	struct dev *c = nullptr;
	struct dev *dev = nullptr;
	
	/* If major == 0, create a dynamic major number */
	if(major == 0)
	{
		major = __allocate_dynamic_major();
		if(major == (unsigned int) -1)
			return nullptr;
	}

	/* Create a new dev and set it up */
	dev = (struct dev *) zalloc(sizeof(struct dev));
	if(!dev)
		return nullptr;
	
	dev->majorminor = MKDEV(major, minor);
	dev->name = strdup(name);
	if(!dev->name)
	{
		free(dev);
		return nullptr;
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
				return errno = EEXIST, nullptr;
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
		return nullptr;

	for(struct dev *c = devices[major]; c; c = c->next)
	{
		if(MINOR(c->majorminor) == minor)
		{
			return c;
		}
	}

	return nullptr;
}

struct file *dev_root = nullptr;
void devfs_init(void)
{
	/* Mount tmpfs on /dev */
	assert(tmpfs_mount("/dev") == 0);

	struct file *dev = dev_root = open_vfs(get_fs_root(), "/dev");

	assert(dev != nullptr);
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(devfs_init);

int device_mknod(struct dev *d, const char *path, const char *name, mode_t mode)
{
	struct file *root = dev_root;

	if(strcmp(path, DEVICE_NO_PATH) != 0)
	{
		root = open_vfs(root, path);
		if(!root)
			return -errno;
	}

	assert(root != nullptr);
	
	if(d->is_block) mode |= S_IFBLK;
	else	mode |= S_IFCHR;
	 

	return mknod_vfs(name, mode, d->majorminor, root->f_dentry) == nullptr;
}

int device_show(struct dev *d, const char *path, mode_t mode)
{
	return device_mknod(d, path, d->name, mode);
}

int device_create_dir(const char *path)
{
	struct file *i = mkdir_vfs(path, 0600, dev_root->f_dentry);

	return i == nullptr ? -1 : 0;
}
