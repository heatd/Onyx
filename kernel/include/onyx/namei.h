/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_NAMEI_H
#define _ONYX_NAMEI_H

#include <onyx/dentry.h>
#include <onyx/limits.h>
#include <onyx/path.h>

#include <uapi/fcntl.h>

#define LOOKUP_NOFOLLOW                (1 << 0)
#define LOOKUP_FAIL_IF_LINK            (1 << 1)
#define LOOKUP_MUST_BE_DIR             (1 << 2)
#define LOOKUP_INTERNAL_TRAILING_SLASH (1 << 3)
#define LOOKUP_EMPTY_PATH              (1 << 4)
#define LOOKUP_DONT_DO_LAST_NAME       (1 << 5)
#define LOOKUP_INTERNAL_SAW_LAST_NAME  (1U << 31)

__BEGIN_CDECLS
struct file *c_vfs_open(int dirfd, const char *name, unsigned int open_flags, mode_t mode);
__END_CDECLS

#ifdef __cplusplus
expected<file *, int> vfs_open(int dirfd, const char *name, unsigned int open_flags, mode_t mode);
#endif

#endif
