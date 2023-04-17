/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_STAT_H
#define _UAPI_STAT_H

#include <uapi/posix-types.h>
#include <uapi/time_types.h>

#define S_IFMT 0170000

#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFBLK  0060000
#define S_IFREG  0100000
#define S_IFIFO  0010000
#define S_IFLNK  0120000
#define S_IFSOCK 0140000

#define S_TYPEISMQ(buf)  0
#define S_TYPEISSEM(buf) 0
#define S_TYPEISSHM(buf) 0
#define S_TYPEISTMO(buf) 0

#ifdef __is_onyx_kernel

#define S_ISDIR(mode)  (((mode) &S_IFMT) == S_IFDIR)
#define S_ISCHR(mode)  (((mode) &S_IFMT) == S_IFCHR)
#define S_ISBLK(mode)  (((mode) &S_IFMT) == S_IFBLK)
#define S_ISREG(mode)  (((mode) &S_IFMT) == S_IFREG)
#define S_ISFIFO(mode) (((mode) &S_IFMT) == S_IFIFO)
#define S_ISLNK(mode)  (((mode) &S_IFMT) == S_IFLNK)
#define S_ISSOCK(mode) (((mode) &S_IFMT) == S_IFSOCK)
#define st_atime       st_atim.tv_sec
#define st_mtime       st_mtim.tv_sec
#define st_ctime       st_ctim.tv_sec
#endif

struct stat
{
    __dev_t st_dev;
    __ino_t st_ino;
    __nlink_t st_nlink;

    __mode_t st_mode;
    __uid_t st_uid;
    __gid_t st_gid;
    unsigned int __pad0;
    __dev_t st_rdev;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;

    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    long __unused[3];
};

#define UTIME_NOW  0x3fffffff
#define UTIME_OMIT 0x3ffffffe

#endif
