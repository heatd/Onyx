/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <onyx/vfs.h>
#include <onyx/mtable.h>
#include <onyx/mutex.h>
#include <onyx/file.h>

static mountpoint_t *mtable = nullptr;
static size_t nr_mtable_entries = 0;
static DECLARE_MUTEX(mtable_lock);

struct file *mtable_lookup(struct file *mountpoint)
{
	if(!mtable)
		return errno = ENOENT, nullptr;
	mutex_lock(&mtable_lock);
	for(size_t i = 0; i < nr_mtable_entries; i++)
	{
		/* Found a mountpoint, return its target */
		if(mtable[i].ino == mountpoint->f_ino->i_inode && mtable[i].dev == mountpoint->f_ino->i_dev)
		{
			struct file *mnt = mtable[i].rootfs;
			fd_get(mnt);
			mutex_unlock(&mtable_lock);
			return mnt;
		}
	}

	mutex_unlock(&mtable_lock);
	return errno = ENOENT, nullptr;
}

int mtable_mount(struct file *mountpoint, struct file *rootfs)
{
	assert(mountpoint);
	assert(rootfs);
	mutex_lock(&mtable_lock);
	nr_mtable_entries++;

	mountpoint_t *new_mtable = (mountpoint_t *) malloc(nr_mtable_entries * sizeof(mountpoint_t));
	if(!new_mtable)
	{
		nr_mtable_entries--;
		mutex_unlock(&mtable_lock);
		return errno = ENOMEM, -1;
	}

	if(mtable)
		memcpy(new_mtable, mtable, (nr_mtable_entries-1) * sizeof(mountpoint_t));
	new_mtable[nr_mtable_entries - 1].ino = mountpoint->f_ino->i_inode;
	new_mtable[nr_mtable_entries - 1].dev = mountpoint->f_ino->i_dev;
	new_mtable[nr_mtable_entries - 1].rootfs = rootfs;
	
	fd_get(rootfs);

	mountpoint_t *old = mtable;
	mtable = new_mtable;

	free(old);
	mutex_unlock(&mtable_lock);
	
	return 0;
}
