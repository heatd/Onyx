/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#include <kernel/block.h>

static block_device_t *dev_list = NULL;
/* 
 * Function: block_device_t *blkdev_search(const char *name);
 * Description: Search for 'name' on the linked list
 * Return value: Returns a valid block device on success, NULL on error. Sets errno properly.
 * errno values: EINVAL - invalid argument;
*/
block_device_t *blkdev_search(const char *name)
{
	if(!name)
		return errno = EINVAL, NULL;
	
	block_device_t *dev = dev_list;
	while(dev)
	{
		if(!strcmp((char *) dev->node_path,(char *) name))
			break;
		dev = dev->next;
	}
	return dev;
}
/* 
 * Function: int block_add_device(block_device_t *dev);
 * Description: Adds dev to the registered block devices.
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument
*/
int blkdev_add_device(block_device_t *dev)
{
	if(!dev)
		return errno = EINVAL, -1;
	if(!dev_list)
		dev_list = dev;
	else
	{
		for(; dev_list->next; dev_list = dev_list->next);
		dev_list->next = dev;
	}
	return 0;
}
/*
 * Function: size_t blkdev_read(size_t offset, size_t count, void *buffer, struct blkdev *dev);
 * Description: Reads 'count' bytes from 'dev' to 'buffer', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
ssize_t blkdev_read(size_t offset, size_t count, void *buffer, struct blkdev *dev)
{
	if(!dev)
		return errno = EINVAL, -1;
	if(!buffer)
		return errno = EINVAL, -1;
	if(!dev->read)
		return errno = ENOSYS, -1;
	return dev->read(offset, count, buffer, dev);
}
/* 
 * Function: size_t blkdev_write(size_t offset, size_t count, void *buffer, struct blkdev *dev);
 * Description: Writes 'count' bytes from 'buffer' to 'dev', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
ssize_t blkdev_write(size_t offset, size_t count, void *buffer, struct blkdev *dev)
{
	if(!dev)
		return errno = EINVAL, -1;
	if(!buffer)
		return errno = EINVAL, -1;
	if(!dev->write)
		return errno = ENOSYS, -1;
	return dev->write(offset, count, buffer, dev);
}
/*
 * Function: int blkdev_flush(struct blkdev *dev);
 * Description: Flushes storage device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
int blkdev_flush(struct blkdev *dev)
{
	if(!dev)
		return errno = EINVAL, -1;
	if(!dev->flush)
		return errno = ENOSYS, -1;
	return dev->flush(dev);
}
/* 
 * Function: int blkdev_power(int op, struct blkdev *dev);
 * Description: Performs power management operation 'op' on device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
int blkdev_power(int op, struct blkdev *dev)
{
	if(!dev)
		return errno = EINVAL, -1;
	if(!dev->power)
		return errno = ENOSYS, -1;
	return dev->power(op, dev);
}
