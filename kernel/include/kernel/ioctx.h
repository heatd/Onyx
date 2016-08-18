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
#ifndef _IOCTX_H
#define _IOCTX_H

#include <kernel/vfs.h>
typedef struct
{
	const char *working_dir;
	vfsnode_t *file_desc[255];
} ioctx_t;

#endif
