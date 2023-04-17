/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_POSIX_TYPES_H
#define _UAPI_POSIX_TYPES_H

#include <onyx/types.h>

typedef int __pid_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef long __clock_t;
typedef unsigned __mode_t;
typedef int __clockid_t;
typedef __u64 __dev_t;
typedef unsigned long __nlink_t;
typedef __u64 __blkcnt_t;
typedef __u64 __ino_t;
typedef long __off_t;
typedef long __blksize_t;
#define __uuid_t_defined
typedef unsigned short __uuid_t[8];

#ifdef __is_onyx_kernel
typedef __mode_t mode_t;
typedef __clockid_t clockid_t;
typedef __dev_t dev_t;
typedef __pid_t pid_t;
typedef __uid_t uid_t;
typedef __gid_t gid_t;
typedef __nlink_t nlink_t;
typedef __blkcnt_t blkcnt_t;
typedef __ino_t ino_t;
typedef __blksize_t blksize_t;
typedef __uuid_t uuid_t;

#if !defined(__DEFINED_off_t)
/* Hack for kernel stdio.h */
typedef __off_t off_t;
#define __DEFINED_off_t
#endif
#endif

#if !defined(__DEFINED_struct_iovec)
/* Hack for kernel - libc compat*/
struct iovec
{
    void *iov_base;
    __usize iov_len;
};

#define __DEFINED_struct_iovec
#endif

#endif
