/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>

#include <kernel/dev.h>
#include <kernel/panic.h>
#include <kernel/compiler.h>

size_t zero_read(size_t offset, size_t count, void *buf, vfsnode_t *n)
{
	/* While reading from /dev/zero, all you read is zeroes. Just memset the buf. */
	UNUSED(offset);
	UNUSED(n);
	memset(buf, 0, count);
	return count;
}
void zero_init()
{
	vfsnode_t *n = creat_vfs(slashdev, "/dev/zero", 0666);
	if(!n)
		panic("Could not create /dev/zero!\n");
	n->type = VFS_TYPE_BLOCK_DEVICE;
	
	struct minor_device *min = dev_register(1, 0);
	if(!min)
		panic("Could not create a device ID for /dev/zero!\n");
	
	min->fops = malloc(sizeof(struct file_ops));
	if(!min->fops)
		panic("Could not create a file operation table for /dev/zero!\n");
	memset(min->fops, 0, sizeof(struct file_ops));

	min->fops->read = zero_read;
	n->dev = min->majorminor;
}
