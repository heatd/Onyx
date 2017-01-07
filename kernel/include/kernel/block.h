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
#ifndef _KERNEL_BLOCK_H
#define _KERNEL_BLOCK_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/types.h>

/* Power management operations*/
#define BLKDEV_PM_SLEEP 1
#define BLKDEV_PM_SHUTDOWN 2
#define BLKDEV_PM_RESET 3
struct blkdev;
typedef ssize_t (*__blkread)(size_t offset, size_t count, void* buffer, struct blkdev* this);
typedef ssize_t (*__blkwrite)(size_t offset, size_t count, void* buffer, struct blkdev* this);
typedef int (*__blkflush)(struct blkdev* this);
typedef int (*__blkpowermanagement)(int op, struct blkdev* this);
typedef struct blkdev
{
	__blkread read;
	__blkwrite write;
	__blkflush flush;
	__blkpowermanagement power;
	const char *node_path; /* A /dev path */
	void *device_info;
	struct blkdev *next;
} block_device_t;

/* 
 * Function: block_device_t *blkdev_search(const char *name);
 * Description: Search for 'name' on the linked list
 * Return value: Returns a valid block device on success, NULL on error. Sets errno properly.
 * errno values: EINVAL - invalid argument;
*/
block_device_t *blkdev_search(const char *name);
/* 
 * Function: int block_add_device(block_device_t *dev);
 * Description: Adds dev to the registered block devices.
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument
*/
int blkdev_add_device(block_device_t *dev);
/*
 * Function: size_t blkdev_read(size_t offset, size_t count, void *buffer, struct blkdev *dev);
 * Description: Reads 'count' bytes from 'dev' to 'buffer', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
ssize_t blkdev_read(size_t offset, size_t count, void *buffer, struct blkdev *dev);
/* 
 * Function: size_t blkdev_write(size_t offset, size_t count, void *buffer, struct blkdev *dev);
 * Description: Writes 'count' bytes from 'buffer' to 'dev', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
ssize_t blkdev_write(size_t offset, size_t count, void *buffer, struct blkdev *dev);
/* 
 * Function: int blkdev_flush(struct blkdev *dev);
 * Description: Flushes storage device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
int blkdev_flush(struct blkdev *dev);
/* 
 * Function: int blkdev_power(int op, struct blkdev *dev);
 * Description: Performs power management operation 'op' on device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
int blkdev_power(int op, struct blkdev *dev);

#endif
