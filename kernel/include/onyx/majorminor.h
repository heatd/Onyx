/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_MAJORMINOR_H
#define _ONYX_MAJORMINOR_H

#define MAJOR_MASK   0xffff0000
#define MAJOR_SHIFT  16
#define MINOR_MASK   0x0000ffff

#define MAJOR(x) (unsigned int) ((x & 0xffff0000) >> MAJOR_SHIFT)
#define MINOR(x) (unsigned int) (x & 0x0000ffff)

#define MKDEV(major, minor) ((major << MAJOR_SHIFT) | minor)

#define MAX_MAJOR_NR   0xffff
#define MAX_MINOR_NR   0xffff

#endif
