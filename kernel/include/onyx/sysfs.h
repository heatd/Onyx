/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SYSFS_H
#define _KERNEL_SYSFS_H

#include <stdbool.h>

#include <onyx/list.h>
/* Each sysfs entry is a sysfs property */
struct sysfs_file
{
	char *name;
	struct sysfs_file *children, *next;
	ino_t inode;
	int type;
	int perms;
	void *priv;
	ssize_t (*write)(void *buffer, size_t size, off_t off);
	ssize_t (*read)(void *buffer, size_t size, off_t off);
};

#ifdef __cplusplus
extern "C" {
#endif
void sysfs_init(void);
struct sysfs_file *sysfs_create_entry(const char *pathname, int mode, struct inode *node);
void sysfs_mount(void);
struct sysfs_file *sysfs_add_device(struct device *dev);
struct sysfs_file *sysfs_add_bus(struct bus *bus);
struct sysfs_file *sysfs_create_dir(const char *name, int perm, struct inode *ino);

#ifdef __cplusplus
}
#endif
#endif
