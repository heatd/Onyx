/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_BLOCK_H
#define _KERNEL_BLOCK_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/types.h>

#include <onyx/list.h>
#include <onyx/dev.h>

/* Power management operations*/
#define BLKDEV_PM_SLEEP 1
#define BLKDEV_PM_SHUTDOWN 2
#define BLKDEV_PM_RESET 3

struct blockdev;
typedef ssize_t (*__blkread)(size_t offset, size_t count, void* buffer, struct blockdev* this);
typedef ssize_t (*__blkwrite)(size_t offset, size_t count, void* buffer, struct blockdev* this);
typedef int (*__blkflush)(struct blockdev* this);
typedef int (*__blkpowermanagement)(int op, struct blockdev* this);

struct blockdev
{
	__blkread read;
	__blkwrite write;
	__blkflush flush;
	__blkpowermanagement power;
	const char *name;
	unsigned int sector_size;
	unsigned int nr_sectors;
	void *device_info;
	struct dev *dev;
	struct list_head block_dev_head;
	struct blockdev *actual_blockdev;	// isn't null when blockdev is a partition
	size_t offset;
};

static inline bool blkdev_is_partition(struct blockdev *dev)
{
	return dev->actual_blockdev != NULL;
}

static inline struct blockdev *blkdev_get_dev(struct file *f)
{
	return f->f_ino->i_helper;
}

#ifdef __cplusplus
extern "C" {
#endif
/* 
 * Function: struct blockdev *blkdev_search(const char *name);
 * Description: Search for 'name' on the linked list
 * Return value: Returns a valid block device on success, NULL on error. Sets errno properly.
 * errno values: EINVAL - invalid argument;
*/
struct blockdev *blkdev_search(const char *name);
/* 
 * Function: int blkdev_init(struct blockdev *dev);
 * Description: Adds dev to the registered block devices and initializes it.
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument
*/
int blkdev_init(struct blockdev *dev);
/*
 * Function: size_t blkdev_read(size_t offset, size_t count, void *buffer, struct blockdev *dev);
 * Description: Reads 'count' bytes from 'dev' to 'buffer', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
ssize_t blkdev_read(size_t offset, size_t count, void *buffer, struct blockdev *dev);
/* 
 * Function: size_t blkdev_write(size_t offset, size_t count, void *buffer, struct blockdev *dev);
 * Description: Writes 'count' bytes from 'buffer' to 'dev', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
ssize_t blkdev_write(size_t offset, size_t count, void *buffer, struct blockdev *dev);
/* 
 * Function: int blkdev_flush(struct blockdev *dev);
 * Description: Flushes storage device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
int blkdev_flush(struct blockdev *dev);
/* 
 * Function: int blkdev_power(int op, struct blockdev *dev);
 * Description: Performs power management operation 'op' on device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
int blkdev_power(int op, struct blockdev *dev);

#ifdef __cplusplus
}
#endif
#endif
