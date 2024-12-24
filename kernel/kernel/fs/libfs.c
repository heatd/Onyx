/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/dentry.h>
#include <onyx/libfs.h>
#include <onyx/vfs.h>

off_t libfs_put_dots(struct dirent *buf, off_t off, struct dentry *dent)
{
    struct dentry *parent = NULL;
    struct inode *ino;
    const char *name = NULL;

    DCHECK(off < 2);
    if (off == 0)
    {
        /* . , fallthrough */
        name = ".";
    }
    else if (off == 1)
    {
        /* .. */
        parent = dentry_parent(dent);
        if (parent)
            dent = parent;
        name = "..";
    }

    ino = dent->d_inode;
    put_dir(name, off, ino->i_inode, IFTODT(ino->i_mode), buf);
    if (parent)
        dput(parent);
    return off + 1;
}

void put_dir(const char *name, off_t off, ino_t ino, unsigned int dtype, struct dirent *buf)
{
    size_t len = strlen(name);
    memcpy(buf->d_name, name, len);
    buf->d_name[len] = '\0';
    buf->d_off = off;
    buf->d_ino = ino;
    buf->d_type = dtype;
    buf->d_reclen = sizeof(struct dirent) - (256 - (len + 1));
}
