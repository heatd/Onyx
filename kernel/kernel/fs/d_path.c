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

static void walk_path(const struct path *path, const struct path *root, struct rbuf *rbuf)
{
    /* TODO: While d_parent on .. Just Works, we don't need to keep track of the struct mnt. This
     * will need to be changed once that changes (mnt should keep track of mnt_parent).
     **/
    struct dentry *dentry = path->dentry;

    prepend_char(rbuf, '\0');
    while (dentry != NULL && dentry != root->dentry)
    {
        if (dentry->d_flags & DENTRY_FLAG_MOUNT_ROOT)
            goto skip;
        prepend_dentry(rbuf, dentry);
        prepend_char(rbuf, '/');
    skip:
        dentry = dentry->d_parent;
    }

    if (*rbuf->buf != '/')
        prepend_char(rbuf, '/');
}

static char *__d_path(const struct path *path, const struct path *root, char *buf,
                      unsigned int buflen)
{
    struct rbuf rbuf0 = {buf + buflen, buflen}, rbuf1;
    unsigned int seq = 0, m_seq = 0;
    rcu_read_lock();

retry_mnt:
    read_seqbegin_or_lock(&mount_lock, &m_seq);

retry:
    read_seqbegin_or_lock(&rename_lock, &seq);
    rbuf1 = rbuf0;
    walk_path(path, root, &rbuf1);

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
    return rbuf_path(&rbuf1);
}

char *d_path(const struct path *path, char *buf, unsigned int buflen)
{
    struct path root = get_filesystem_root();
    char *ret = __d_path(path, &root, buf, buflen);
    path_put(&root);
    return ret;
}
