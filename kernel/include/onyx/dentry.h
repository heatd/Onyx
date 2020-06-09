/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_DENTRY_H
#define _ONYX_DENTRY_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include <onyx/vfs.h>
#include <onyx/rwlock.h>
#include <onyx/list.h>
#include <onyx/fnv.h>

#define INLINE_NAME_MAX			40

#define DENTRY_FLAG_MOUNTPOINT               (1 << 0)

struct dentry
{
	unsigned long d_ref;
	struct rwlock d_lock;

	char *d_name;
	char d_inline_name[INLINE_NAME_MAX];
	fnv_hash_t d_name_hash; 
	size_t d_name_length;
	struct inode *d_inode;

	struct dentry *d_parent;
	struct list_head d_parent_dir_node;
	struct list_head d_children_head;
	struct dentry *d_mount_dentry;
	uint16_t d_flags;
};

#ifdef __cplusplus
extern "C"
{
#endif

struct dentry *dentry_open(char *path, struct dentry *base);
struct dentry *dentry_mount(const char *mountpoint, struct inode *inode);
void dentry_init(void);

#ifdef __cplusplus
}
#endif

#endif
