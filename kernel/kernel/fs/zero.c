/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>

#include <kernel/dev.h>
size_t zero_read(size_t offset, size_t count, void *buf, vfsnode_t *n)
{
	/* While reading from /dev/zero, all you read is zeroes. Just memset the buf. */
	(void) offset;
	(void) n;
	memset(buf, 0, count);
	return count;
}
void zero_init()
{
	vfsnode_t *n = creat_vfs(slashdev, "/dev/zero", 0666);
	n->type = VFS_TYPE_BLOCK_DEVICE;
	n->read = zero_read;
}
