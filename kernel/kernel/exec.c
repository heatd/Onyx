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
#include <kernel/task_switching.h>
#include <kernel/elf.h>
#include <kernel/vfs.h>
int exec(const char *path)
{
	vfsnode_t *in = vfs_findnode(path);
	if (!in)
		return errno = ENOENT;
	size_t size = in->size;
	char *buffer = malloc(size);
	if (!buffer)
		return errno = ENOMEM;
	size_t read = in->read(0, size, buffer, in);
	if (read != size)
		return errno = EAGAIN;
	void *entry = elf_load((void *) buffer);
	sched_create_thread((ThreadCallback) entry, 0, NULL);
	return 0;
}
