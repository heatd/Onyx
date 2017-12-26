/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <sys/types.h>

#include <onyx/dev.h>
#include <onyx/majorminor.h>
#include <onyx/compiler.h>
#include <onyx/panic.h>

struct inode *slashdev = NULL;
struct inode **children = NULL;
size_t num_child = 0;
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
		first_minor = major_devices[major_to_hash(major)]->subdevs;
		for(; c->next; c = c->next);
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

off_t devfs_getdirent(struct dirent *buf, off_t off, struct inode *inode)
{
	off_t new_off = off + 1;
	if((size_t) off > num_child)
		return 0;

	buf->d_ino = children[off]->inode;
	strcpy(buf->d_name, children[off]->name);
	if(children[off]->type & VFS_TYPE_DIR) buf->d_type = DT_DIR;
	else if(children[off]->type & VFS_TYPE_FILE) buf->d_type = DT_REG;
	else if(children[off]->type & VFS_TYPE_CHAR_DEVICE) buf->d_type = DT_CHR;
	else if(children[off]->type & VFS_TYPE_BLOCK_DEVICE) buf->d_type = DT_BLK;
	else buf->d_type = DT_UNKNOWN;
	buf->d_off = off;

	buf->d_reclen = sizeof(struct dirent) - (256 - (strlen(buf->d_name) + 1));
	return new_off;
}

struct inode *devfs_open(struct inode *this, const char *name)
{
	if(!children)
		return errno = ENOENT, NULL;
	char *path = vfs_get_full_path(this, (char*) name);
	if(!path)
		return errno = ENOMEM, NULL;
	for(size_t i = 0; i < num_child; i++)
	{
		if(strcmp(path, (char*) children[i]->name) == 0)
		{
			free(path);
			return children[i];
		}
	}
	free(path);
	return errno = ENOENT, NULL;
}
struct inode *devfs_creat(const char *pathname, int mode, struct inode *self)
{
	UNUSED(self);
	if(!children)
	{
		num_child++;
		children = malloc(sizeof(void*) * num_child);
		if(!children)
		{
			num_child--;
			return errno = ENOMEM, NULL;
		}

		children[0] = malloc(sizeof(struct inode));
		if(!children[0])
		{
			free(children);
			children = NULL;
			num_child--;
			return errno = ENOMEM, NULL;
		}
		memset(children[0], 0, sizeof(struct inode));

		children[0]->name = vfs_get_full_path(self, (char*)pathname);
		children[0]->inode = 0;
		children[0]->type = VFS_TYPE_FILE;
		children[0]->refcount++;
		return children[0];
	}
	else
	{
		num_child++;
		/* Save the pointer in case realloc fails, so the whole /dev tree doesn't crash */
		struct inode **old_children = children;

		children = realloc(children, sizeof(void*) * num_child);
		if(!children)
		{
			/* Restore the old data */
			num_child--;
			children = old_children;
			return errno = ENOMEM, NULL;
		}
		children[num_child-1] = malloc(sizeof(struct inode));
		if(!children[num_child-1])
		{
			/* Restore the old data */
			num_child--;
			return errno = ENOMEM, NULL;
		}
		memset(children[num_child-1], 0, sizeof(struct inode));

		children[num_child-1]->name = vfs_get_full_path(self, (char*)pathname);
		children[num_child-1]->inode = num_child-1;
		children[num_child-1]->type = VFS_TYPE_FILE;
		children[num_child-1]->refcount++;
		return children[num_child-1];
	}
}

struct file_ops devfs_ops = 
{
	.open = devfs_open,
	.getdirent = devfs_getdirent,
	.creat = devfs_creat
};

int devfs_init()
{
	struct inode *i = open_vfs(fs_root, "/dev");
	if(unlikely(!i))
		panic("/dev not found!");

	slashdev = malloc(sizeof(struct inode));
	if(!slashdev)
		panic("Out-of-memory while creating /dev!");
	memset(slashdev, 0, sizeof(struct inode));

	slashdev->name = "/dev";
	slashdev->type = VFS_TYPE_DIR;
	slashdev->refcount++;
	memcpy(&slashdev->fops, &devfs_ops, sizeof(struct file_ops));
	mount_fs(slashdev, "/dev");
	return 0;
}
