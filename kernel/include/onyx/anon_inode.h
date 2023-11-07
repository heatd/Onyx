/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_ANON_INODE_H
#define _ONYX_ANON_INODE_H

#include <onyx/types.h>

#include <uapi/stat.h>

struct inode;
struct file;
struct file_ops;

struct inode *anon_inode_alloc(mode_t file_type = S_IFREG);
struct file *anon_inode_open(mode_t file_type, struct file_ops *ops, const char *name);

#endif
