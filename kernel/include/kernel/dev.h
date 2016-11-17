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
#include <stdint.h>

#include <kernel/vfs.h>

typedef struct
{
	__read read;
	__write write;
	__open open;
	__close close;
	__getdents getdents;
	__ioctl ioctl;
} fs_device_t;