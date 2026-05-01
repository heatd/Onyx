/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/proc.h>
#include <onyx/seq_file.h>

static int version_show(struct seq_file *m, void *ptr)
{
    seq_printf(m, "onyx-rolling\n");
    return 0;
}

static int proc_version_open(struct file *filp)
{
    return single_open(filp, version_show, NULL);
}

static const struct proc_file_ops proc_version_ops = {
    .open = proc_version_open,
    .read_iter = seq_read_iter,
    .release = seq_release,
};

static __init void proc_version_init(void)
{
    procfs_add_entry("version", 0444, NULL, &proc_version_ops);
}
