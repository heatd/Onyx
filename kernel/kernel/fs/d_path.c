/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <sys/mount.h>

#include <onyx/compiler.h>
#include <onyx/cred.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/mm/slab.h>
#include <onyx/mount.h>
#include <onyx/rculist.h>
#include <onyx/rcupdate.h>
#include <onyx/seqlock.h>
#include <onyx/vfs.h>

struct rbuf
{
    char *buf;
    int len;
};

static char *rbuf_path(struct rbuf *rbuf)
{
    if (rbuf->len < 0)
        return ERR_PTR(-ENAMETOOLONG);
    return rbuf->buf;
}

static void prepend_char(struct rbuf *rbuf, char c)
{
    rbuf->len--;
    if (rbuf->len >= 0)
    {
        rbuf->buf--;
        *rbuf->buf = c;
    }
}

static void prepend_str(struct rbuf *rbuf, const char *str, size_t len)
{
    rbuf->len -= len;
    if (rbuf->len >= 0)
    {
        rbuf->buf -= len;
        memcpy(rbuf->buf, str, len);
    }
}

static void prepend_dentry(struct rbuf *rbuf, struct dentry *dentry)
{
    /* TODO: we should RCU-protect d_name */
    spin_lock(&dentry->d_lock);
    prepend_str(rbuf, dentry->d_name, dentry->d_name_length);
    spin_unlock(&dentry->d_lock);
}

static bool follow_mount_up(struct mount *mnt, struct path *out)
{
    struct dentry *dentry = mnt->mnt_root, *mountpoint;

    while (mnt->mnt_parent)
    {
        mountpoint = mnt->mnt_point;
        mnt = mnt->mnt_parent;
        if (mnt->mnt_root != dentry)
        {
            out->mount = mnt;
            out->dentry = mountpoint;
            return true;
        }
    }

    return false;
}

enum walk_path_result
{
    WALK_PATH_OK = 0,
    WALK_PATH_OUT_OF_ROOT,
};

static enum walk_path_result walk_path(const struct path *path, const struct path *root,
                                       struct rbuf *rbuf)
{
    struct dentry *dentry = path->dentry;
    struct mount *mnt = path->mount;
    enum walk_path_result ret = WALK_PATH_OK;

    prepend_char(rbuf, '\0');
    while (dentry != NULL && dentry != root->dentry)
    {
        while (dentry == mnt->mnt_root)
        {
            struct path p;
            if (!follow_mount_up(mnt, &p))
            {
                ret = WALK_PATH_OUT_OF_ROOT;
                break;
            }
            dentry = p.dentry;
            mnt = p.mount;
        }

        prepend_dentry(rbuf, dentry);
        prepend_char(rbuf, '/');
        dentry = dentry->d_parent;
    }

    if (*rbuf->buf != '/')
        prepend_char(rbuf, '/');
    return ret;
}

#define D_PATH_NO_ESCAPE_ROOT (1 << 0)

static char *__d_path(const struct path *path, const struct path *root, char *buf,
                      unsigned int buflen, unsigned int flags)
{
    struct rbuf rbuf0 = {buf + buflen, buflen}, rbuf1;
    unsigned int seq = 0, m_seq = 0;
    enum walk_path_result res;
    rcu_read_lock();

retry_mnt:
    read_seqbegin_or_lock(&mount_lock, &m_seq);

retry:
    read_seqbegin_or_lock(&rename_lock, &seq);
    rbuf1 = rbuf0;
    res = walk_path(path, root, &rbuf1);

    if (read_seqretry(&rename_lock, seq))
    {
        seq = 1;
        goto retry;
    }

    done_seqretry(&rename_lock, seq);

    if (read_seqretry(&mount_lock, m_seq))
    {
        m_seq = 1;
        goto retry_mnt;
    }

    done_seqretry(&mount_lock, m_seq);
    rcu_read_unlock();

    if (res == WALK_PATH_OUT_OF_ROOT && (flags & D_PATH_NO_ESCAPE_ROOT))
        return NULL;
    return rbuf_path(&rbuf1);
}

char *d_path(const struct path *path, char *buf, unsigned int buflen)
{
    struct path root = get_filesystem_root();
    char *ret = __d_path(path, &root, buf, buflen, 0);
    path_put(&root);
    return ret;
}

char *d_path_under_root(const struct path *path, const struct path *root, char *buf,
                        unsigned int buflen)
{
    char *ret;
    struct path root2;
    if (!root)
    {
        root2 = get_filesystem_root();
        root = &root2;
    }

    ret = __d_path(path, root, buf, buflen, D_PATH_NO_ESCAPE_ROOT);

    if (root == &root2)
        path_put(&root2);
    return ret;
}
