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
#include <fcntl.h>

#include <onyx/block.h>
#include <onyx/rwlock.h>
#include <onyx/page.h>
#include <partitions.h>

static struct rwlock dev_list_lock;
static struct list_head dev_list = LIST_HEAD_INIT(dev_list);

/* 
 * Function: struct blockdev *blkdev_search(const char *name);
 * Description: Search for 'name' on the linked list
 * Return value: Returns a valid block device on success, NULL on error. Sets errno properly.
 * errno values: EINVAL - invalid argument;
*/
struct blockdev *blkdev_search(const char *name)
{
	assert(name != NULL);
	
	rw_lock_read(&dev_list_lock);

	list_for_every(&dev_list)
	{
		struct blockdev *blk = container_of(l, struct blockdev, block_dev_head);
		if(!strcmp(blk->name, name))
		{
			rw_unlock_read(&dev_list_lock);
			return blk;
		}
	}

	rw_unlock_read(&dev_list_lock);

	return NULL;
}

unsigned int blkdev_ioctl(int request, void *argp, struct inode *ino)
{
	struct blockdev *d = ino->i_helper;

	(void) d;	
	switch(request)
	{
		default:
			return -EINVAL;
	}
}

size_t blkdev_read_file(int flags, size_t offset, size_t len, void *buffer, struct inode *ino)
{
	if(flags & O_NONBLOCK)
		return errno = EWOULDBLOCK, -1;

	struct blockdev *d = ino->i_helper;
	/* align the offset first */
	size_t misalignment = offset % d->sector_size;
	ssize_t sector = offset / d->sector_size;
	size_t read = 0;
	char *buf = buffer;

	if(misalignment != 0)
	{
		//printk("handling misalignment\n");
		/* *sigh* yuck, we'll need to allocate a bounce buffer */
		struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
		if(!p)
		{
			return errno = ENOMEM, -1;
		}

		void *virt = PAGE_TO_VIRT(p);

		//printk("reading sector %lu, %u bytes\n", sector, d->sector_size);
	
		ssize_t s = blkdev_read(sector * d->sector_size, d->sector_size, virt, d);

		size_t to_copy = min((d->sector_size - misalignment), len);
	 
		if(s < 0)
		{
			free_page(p);
			return -1;
		}

	
		memcpy(buf, (char *) virt + misalignment, to_copy);

		free_page(p);

		sector++;
		read = to_copy;
		buf += read;
		len -= read;
		//printk("len: %lu\n", len);
	}

	//printk("len: %lu\n", len);

	if(len != 0 && len / d->sector_size)
	{
		size_t nr_sectors = len / d->sector_size;
		size_t reading = nr_sectors * d->sector_size;

		//printk("Read: %lu\n", read);
		//printk("here, buf %p\n", buf);
		ssize_t s = blkdev_read(sector * d->sector_size, reading, buf, d);
		if(s < 0)
		{
			return errno = ENXIO, -1;
		}

		len -= reading;
		buf += reading;
		read += reading;
		sector += nr_sectors;
	}

	if(len != 0)
	{
		struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
		if(!p)
		{
			return errno = ENOMEM, -1;
		}

		void *virt = PAGE_TO_VIRT(p);

		ssize_t s = blkdev_read(sector * d->sector_size, d->sector_size, virt, d);
	
		if(s < 0)
		{
			free_page(p);
			return -1;
		}

		memcpy(buf, (char *) virt, len);

		free_page(p);

		sector++;
		read += len;
		buf += len;
		len -= len;
	}

	return read;
}

size_t blkdev_write_file(size_t offset, size_t len, void* buffer, struct inode *ino)
{
	struct blockdev *d = ino->i_helper;
	/* align the offset first */
	size_t misalignment = offset % d->sector_size;
	ssize_t sector = offset / d->sector_size;
	size_t written = 0;
	char *buf = buffer;

	if(misalignment != 0)
	{
		/* *sigh* yuck, we'll need to allocate a bounce buffer */
		/* TODO: Check how fast the page allocator is vs malloc */
		struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
		if(!p)
		{
			return errno = ENOMEM, -1;
		}

		void *virt = PAGE_TO_VIRT(p);

		ssize_t s = blkdev_read(sector * d->sector_size, d->sector_size, virt, d);
	
		size_t to_copy = min((d->sector_size - misalignment), len);
		
		if(s < 0)
		{
			free_page(p);
			return -1;
		}

		memcpy((char *) virt + misalignment, buf, to_copy);

		s = blkdev_write(sector * d->sector_size, d->sector_size, virt, d);
		free_page(p);

		if(s < 0)
		{
			return -1;
		}

		sector++;
		written += to_copy;
		buf += to_copy;
		len -= to_copy;
	}

	if(len != 0)
	{
		size_t nr_sectors = len / d->sector_size;
		size_t writing = nr_sectors * d->sector_size;

		ssize_t s = blkdev_write(sector * d->sector_size, writing, buf, d);
		if(s < 0)
		{
			return errno = ENXIO, -1;
		}

		len -= writing;
		buf += writing;
		written += writing;
		sector += nr_sectors;
	}

	if(len != 0)
	{
		struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
		if(!p)
		{
			return errno = ENOMEM, -1;
		}

		void *virt = PAGE_TO_VIRT(p);

		ssize_t s = blkdev_read(sector * d->sector_size, d->sector_size, virt, d);
	
		if(s < 0)
		{
			free_page(p);
			return -1;
		}

		memcpy(buf, (char *) virt, len);

		s = blkdev_write(sector * d->sector_size, d->sector_size, virt, d);
		free_page(p);

		if(s < 0)
		{
			return -1;
		}

		sector++;
		written += len;
		buf += len;
		len -= len;
	}

	return written;

}

int blkdev_init(struct blockdev *blk)
{
	assert(blk != NULL);

	rw_lock_write(&dev_list_lock);

	list_add_tail(&blk->block_dev_head, &dev_list);

	rw_unlock_write(&dev_list_lock);

	struct dev *dev = blk->dev;
	dev->is_block = true;
	dev->fops.ioctl = blkdev_ioctl;
	dev->fops.read = blkdev_read_file;
	dev->fops.write = blkdev_write_file;
	dev->priv = blk;

	device_show(dev, DEVICE_NO_PATH, 0600);

	if(!blkdev_is_partition(blk))
		partition_setup_disk(blk);

	return 0;
}
/*
 * Function: size_t blkdev_read(size_t offset, size_t count, void *buffer, struct blockdev *dev);
 * Description: Reads 'count' bytes from 'dev' to 'buffer', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
*/
ssize_t blkdev_read(size_t offset, size_t count, void *buffer, struct blockdev *dev)
{
	if(count == 0)
		return 0;
	
	if(blkdev_is_partition(dev))
		return blkdev_read(dev->offset + offset, count, buffer, dev->actual_blockdev);
	if(!dev->read)
		return errno = EIO, -1;

	return dev->read(offset, count, buffer, dev);
}
/* 
 * Function: size_t blkdev_write(size_t offset, size_t count, void *buffer, struct blockdev *dev);
 * Description: Writes 'count' bytes from 'buffer' to 'dev', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; EIO - operation not supported on storage device 'dev'
*/
ssize_t blkdev_write(size_t offset, size_t count, void *buffer, struct blockdev *dev)
{
	if(count == 0)
		return 0;

	if(blkdev_is_partition(dev))
		return blkdev_write(dev->offset + offset, count, buffer, dev->actual_blockdev);
	if(!dev->write)
		return errno = EIO, -1;

	return dev->write(offset, count, buffer, dev);
}
/*
 * Function: int blkdev_flush(struct blockdev *dev);
 * Description: Flushes storage device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; EIO - operation not supported on storage device 'dev'
*/
int blkdev_flush(struct blockdev *dev)
{
	if(blkdev_is_partition(dev))
		return blkdev_flush(dev->actual_blockdev);
	if(!dev->flush)
		return errno = ENOSYS, -1;

	return dev->flush(dev);
}
/* 
 * Function: int blkdev_power(int op, struct blockdev *dev);
 * Description: Performs power management operation 'op' on device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; EIO - operation not supported on storage device 'dev'
*/
int blkdev_power(int op, struct blockdev *dev)
{
	if(blkdev_is_partition(dev))
		return blkdev_power(op, dev->actual_blockdev);
	if(!dev->power)
		return errno = EIO, -1;


	return dev->power(op, dev);
}
