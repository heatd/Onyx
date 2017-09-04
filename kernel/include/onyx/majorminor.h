/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_MAJORMINOR_H
#define _KERNEL_MAJORMINOR_H

#define MAJOR(x) (x >> 16)
#define MINOR(x) (x & 0xFFFF)

#define MKDEV(major, minor) ((major << 16) | minor)
#endif