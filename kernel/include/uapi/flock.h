/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_FLOCK_H
#define _UAPI_FLOCK_H

#include <onyx/types.h>

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

#define L_SET  0
#define L_INCR 1
#define L_XTND 2

struct flock
{
    short l_type;
    short l_whence;
    __off_t l_start;
    __off_t l_len;
    __pid_t l_pid;
};

#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2

#endif
