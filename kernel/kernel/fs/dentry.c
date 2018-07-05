/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#undef _BSD_SOURCE
#define _BSD_SOURCE
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <onyx/dentry.h>
#include <onyx/compiler.h>
#include <onyx/slab.h>
#include <onyx/atomic.h>
#include <onyx/vfs.h>

#if 0
slab_cache_t *dentry_cache = NULL;
struct dentry *root_dentry = NULL;

/* HUGE TODO */
void dentry_dtor(void *ptr)
{
	struct dentry *dentry = ptr;

	acquire_spinlock(&dentry->d_lock);

	object_unref(&dentry->d_inode->i_object);

	if(dentry->d_parent)
		object_unref(&dentry->d_parent->object);
	
	free(dentry->d_name);

	release_spinlock(&dentry->d_lock);
}

struct dentry *dentry_open(struct dentry *dir, const char *name)
{
	printk("Looking up %s\n", name);

	acquire_spinlock(&dir->d_lock);

	for(struct dentry *d = dir->child; d != NULL; d = d->d_next)
	{
		if(strcmp(d->d_name, name) == 0)
		{
			release_spinlock(&dir->d_lock);
			return d;
		}
	}

	struct inode *inode = open_vfs(dir->d_inode, name);

	if(!inode)
	{
		release_spinlock(&dir->d_lock);
	
		return errno = ENOENT, NULL;
	}

	struct dentry *new_d = dentry_create(name, inode);

	new_d->d_parent = dir;
	object_ref(&dir->object);

	dir->last_child->d_next = new_d;
	dir->last_child = new_d;

	release_spinlock(&dir->d_lock);
	return new_d;
}

void dentry_release(struct object *obj)
{
	struct dentry *dentry = (struct dentry *) obj;

	slab_free(dentry_cache, dentry);
}

struct dentry *dentry_create(char *name, struct inode *inode)
{
	struct dentry *d = slab_allocate(dentry_cache);

	if(!d)
		return NULL;

	memset(d, 0, sizeof(*d));

	object_init(&d->object, dentry_release);

	d->object.ref.refcount = 0;

	strcpy(d->d_name, name);
	d->d_inode = inode;

	object_ref(&inode->i_object);

	return d;
}

struct dentry *dentry_init(void)
{
	dentry_cache = slab_create("dentry", sizeof(struct dentry), 0, 0, NULL, dentry_dtor);

	assert(dentry_cache != NULL);

	root_dentry = dentry_create("", get_fs_root());

	assert(root_dentry != NULL);
}

#endif