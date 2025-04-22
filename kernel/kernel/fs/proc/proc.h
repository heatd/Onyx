/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_PROC_INTERNAL_H
#define _ONYX_PROC_INTERNAL_H

#include <onyx/proc.h>

struct dentry;

extern struct proc_file_ops proc_noop;
int proc_pid_open(struct dentry *dir, const char *name, struct dentry *dentry);
int str_to_int(const char *name);
void procfs_init_entry(struct procfs_entry *entry, const char *name, mode_t mode,
                       struct procfs_entry *parent, const struct proc_file_ops *ops);

#endif
