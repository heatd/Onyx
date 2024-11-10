/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PATH_H
#define _ONYX_PATH_H

#include <onyx/dentry.h>
#include <onyx/mount.h>

struct path
{
    struct dentry *dentry;
    struct mount *mount;
};

static inline void path_get(struct path *p)
{
    dget(p->dentry);
    mnt_get(p->mount);
}

static inline void path_put(struct path *p)
{
    if (p->dentry)
        dput(p->dentry);
    if (p->mount)
        mnt_put(p->mount);
}

static inline void path_init(struct path *p)
{
    p->dentry = NULL;
    p->mount = NULL;
}

static inline bool path_is_null(const struct path *p)
{
    return !p->dentry && !p->mount;
}

static inline bool path_is_equal(const struct path *p1, const struct path *p2)
{
    return p1->mount == p2->mount && p1->dentry == p2->dentry;
}

#endif
