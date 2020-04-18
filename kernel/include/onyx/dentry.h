/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_DENTRY_H
#define _ONYX_DENTRY_H

#include <stdint.h>
#include <stddef.h>

#include <onyx/vfs.h>
#include <onyx/spinlock.h>

#if 0
#define NAME_MAX	256

struct dentry
{
	struct object object;

	char d_name[NAME_MAX];
	struct file *d_inode;

	struct dentry *d_parent;
	struct dentry *d_next;

	struct spinlock d_lock;
	struct dentry *child, *last_child;
};

struct dentry *dentry_open(struct dentry *dir, const char *name);
void dentry_init(void);

/* TODO */
#endif
#endif
