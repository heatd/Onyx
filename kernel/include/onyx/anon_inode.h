/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_ANON_INODE_H
#define _ONYX_ANON_INODE_H

#include <onyx/compiler.h>
#include <onyx/types.h>

#include <uapi/stat.h>

struct inode;
struct file;
struct file_ops;

__BEGIN_CDECLS

struct inode *anon_inode_alloc(mode_t file_type
#ifdef __cplusplus
                               = S_IFREG
#endif
);

struct file *anon_inode_open(mode_t file_type, const struct file_ops *ops, const char *name);

__END_CDECLS

#endif
