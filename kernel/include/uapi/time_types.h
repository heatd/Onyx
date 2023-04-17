/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_TIME_TYPES_H
#define _UAPI_TIME_TYPES_H

#include <onyx/types.h>

#include <uapi/posix-types.h>
struct timespec
{
    __s64 tv_sec;
    __s64 tv_nsec;
};

struct timeval
{
    __s64 tv_sec;
    __s64 tv_usec;
};

typedef long __time_t;

#ifdef __is_onyx_kernel
typedef __time_t time_t;
#endif

#endif
