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
#include <kernel/panic.h>
#include <kernel/process.h>
int exec(const char *path)
{
	process_t *proc = process_create(path, NULL, NULL);
	vfsnode_t *in = open_vfs(fs_root, path);
	if (!in)
	{
		printf("%s: No such file or directory\n",path);
		return errno = ENOENT;
	}
	char *buffer = malloc(in->size);
	if (!buffer)
		return errno = ENOMEM;
	size_t read = read_vfs(0, in->size, buffer, in);
	if (read != in->size)
		return errno = EAGAIN;
	void *entry = elf_load((void *) buffer);
	process_create_thread(proc, (ThreadCallback) entry, 0, NULL);
	return 0;
}
