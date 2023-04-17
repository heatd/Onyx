/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _UAPI_LIMITS_H
#define _UAPI_LIMITS_H

#define NR_OPEN 1024

#define ARG_MAX 131072

#define MAX_CANON 255
#define MAX_INPUT 255
#define PIPE_BUF  4096

#define NAME_MAX 255
#define PATH_MAX 4096
#define LINK_MAX 127

#define XATTR_SIZE_MAX 65536
#define XATTR_NAME_MAX 255
#define XATTR_LIST_MAX 65536

#define RTSIG_MAX 32

#define NGROUPS_MAX 65536

#endif
