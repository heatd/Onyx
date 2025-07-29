/*
 * Copyright (c) 2023 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/anon_inode.h>
#include <onyx/assert.h>
#include <onyx/cred.h>
#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/init.h>
#include <onyx/superblock.h>

#include <onyx/atomic.hpp>

static struct superblock *anonsb;
static atomic<ino_t> next_ino = 3;

__init void anon_sb_init()
{
    anonsb = new superblock;
    CHECK(anonsb != nullptr);
    superblock_init(anonsb, SB_FLAG_NODIRTY | SB_FLAG_IN_MEMORY);
}

struct inode *anon_inode_alloc(mode_t file_type)
{
    DCHECK(anonsb != nullptr);

    struct inode *ino = inode_create(true);
    if (!ino)
        return nullptr;

    ino->i_atime = ino->i_mtime = clock_get_posix_time();
    ino->i_sb = anonsb;
    ino->i_inode = next_ino.fetch_add(1);
    ino->i_mode = file_type | S_IWUSR | S_IRUSR;

    {
        creds_guard<CGType::Read> c;
        ino->i_uid = c.get()->euid;
        ino->i_gid = c.get()->egid;
    }

    superblock_add_inode(anonsb, ino);

    return ino;
}

struct file *anon_inode_open(mode_t file_type, const struct file_ops *ops, const char *name)
{
    struct inode *ino = nullptr;
    struct dentry *dentry = nullptr;
    struct file *f = nullptr;

    ino = anon_inode_alloc(file_type);
    if (!ino)
        return nullptr;

    ino->i_fops = (struct file_ops *) ops;

    dentry = dentry_create(name, ino, nullptr);
    if (!dentry)
        goto err;
    dget(dentry);

    f = inode_to_file(ino);
    if (!f)
        goto err;

    f->f_dentry = dentry;
    f->f_op = ops;
    return f;
err:
    if (dentry)
        dput(dentry);
    if (ino)
        inode_unref(ino);
    return nullptr;
}
