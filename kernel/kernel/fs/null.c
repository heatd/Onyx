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
#include <stdlib.h>
#include <string.h>

#include <kernel/dev.h>

size_t null_write(size_t offset, size_t count, void *buf, vfsnode_t *n)
{
	/* While writing to /dev/null, everything gets discarded. It's basically a no-op. */
	(void) offset;
	(void) count;
	(void) buf;
	(void) n;
	return count;
}
void null_init()
{
	vfsnode_t *n = creat_vfs(slashdev, "/dev/null", 0666);
	n->type = VFS_TYPE_BLOCK_DEVICE;
	n->write = null_write;
}
