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
#ifndef _KERNEL_MAJORMINOR_H
#define _KERNEL_MAJORMINOR_H

#define MAJOR(x) (x >> 16)
#define MINOR(x) (x & 0xFFFF)

#define MKDEV(major, minor) ((major << 16) | minor)
#endif