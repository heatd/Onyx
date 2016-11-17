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
#include <stdio.h>

#include <kernel/vfs.h>
#include <kernel/dev.h>
#include <kernel/compiler.h>

int init_slashdev()
{
	vfsnode_t *i = open_vfs(fs_root, "/dev");
	if(unlikely(!i))
		panic("/dev not found!");
	
}