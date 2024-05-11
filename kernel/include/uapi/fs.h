/*
 * Copyright (c) 2024 Pedro Falcato
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_UAPI_FS_H
#define _ONYX_UAPI_FS_H

#include <uapi/ioctl.h>

/* Filesystem related ioctls */
#define FIBMAP _IOWR('F', 0, unsigned int)

#endif
