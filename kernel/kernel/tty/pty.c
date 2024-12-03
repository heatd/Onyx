/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/init.h>
#include <onyx/libfs.h>
#include <onyx/tty.h>
#include <onyx/vfs.h>

#include <uapi/ioctls.h>

/* TODO: Locking, lifetimes, closing semantics... */

static ssize_t pty_write(const void *buffer, size_t size, struct tty *tty)
{
    struct tty *slave = tty->priv;
    tty_received_buf(slave, buffer, size);
    return size;
}

static const struct file_ops pty_slave_ops;

unsigned long next_pts = 0;

static int pty_slave_on_open(struct file *filp)
{
    int st = 0;
    struct tty *tty = filp->f_ino->i_helper;

    mutex_lock(&tty->lock);

    if (tty->flags & TTY_FLAG_LOCKED_PTY)
    {
        st = -EAGAIN;
        goto out;
    }

    st = ttydev_on_open_unlocked(filp);
    filp->private_data = tty;

out:
    mutex_unlock(&tty->lock);
    return st;
}

static unsigned int pty_ioctl(int request, void *argp, struct tty *tty);

static const struct tty_ops pty_ops = {
    .ioctl = pty_ioctl,
    .write = pty_write,
};

static int pty_master_on_open(struct file *filp)
{
    struct tty *master = tty_init(NULL, NULL, 0);
    struct tty *slave = tty_init(NULL, NULL, TTY_INIT_PTY);
    if (!master || !slave)
        goto out_err;

    /* Wire up the two ttys */
    master->priv = slave;
    slave->priv = master;
    slave->flags |= TTY_FLAG_LOCKED_PTY;
    master->flags |= TTY_FLAG_MASTER_PTY;
    master->ops = slave->ops = &pty_ops;

    slave->tty_num = __atomic_fetch_add(&next_pts, 1, __ATOMIC_RELEASE);

    /* The master tty will not have special input/output processing. we want the raw input more or
     * less. */
    master->term_io.c_iflag = 0;
    master->term_io.c_oflag = 0;
    master->term_io.c_lflag = 0;

    if (pty_register_slave(slave, &pty_slave_ops) < 0)
        goto out_err;

    filp->private_data = master;
    return 0;
out_err:
    /* TODO: Clean up ttys */
    return -ENOMEM;
}

static unsigned int pty_ioctl(int request, void *argp, struct tty *tty)
{
    struct tty *other = tty->priv;
    switch (request)
    {
        case TIOCGPTN: {
            int pty = other->tty_num;
            return copy_to_user(argp, &pty, sizeof(int));
        }

        case TIOCGPTLCK: {
            int locked = other->flags & TTY_FLAG_LOCKED_PTY ? 1 : 0;
            return copy_to_user(argp, &locked, sizeof(int));
        }

        case TIOCSPTLCK: {
            int locked;
            if (copy_from_user(&locked, argp, sizeof(int)) < 0)
                return -EFAULT;
            if (locked)
                other->flags |= TTY_FLAG_LOCKED_PTY;
            else
                other->flags &= ~TTY_FLAG_LOCKED_PTY;
            return 0;
        }
    }

    return -ENOTTY;
}

/* yuck yuck yuck yuck yuck */
#define DEFINE_NEW_HACKY_FILE(filp)       \
    struct inode _ino;                    \
    struct file _f;                       \
    _ino.i_helper = (filp)->private_data; \
    _f.f_ino = &_ino;

static size_t ptydevfs_write(size_t offset, size_t len, void *ubuffer, struct file *f)
{
    DEFINE_NEW_HACKY_FILE(f);
    return ttydevfs_write(offset, len, ubuffer, &_f);
}

static size_t ptydevfs_read(size_t offset, size_t count, void *buffer, struct file *this_)
{
    DEFINE_NEW_HACKY_FILE(this_);
    return ttydevfs_read(offset, count, buffer, &_f);
}

static ssize_t ptydevfs_read_iter(struct file *filp, size_t offset, struct iovec_iter *iter,
                                  unsigned int flags)
{
    DEFINE_NEW_HACKY_FILE(filp);
    return ttydevfs_read_iter(&_f, offset, iter, flags);
}

static unsigned int pty_ioctl_redir(int request, void *argp, struct file *dev)
{
    DEFINE_NEW_HACKY_FILE(dev);
    return tty_ioctl(request, argp, &_f);
}

static short pty_poll(void *poll_file, short events, struct file *f)
{
    DEFINE_NEW_HACKY_FILE(f);
    return tty_poll(poll_file, events, &_f);
}

/* TODO: It's hacky that we need to define all these file ops. And that we need to redirect the pty
 * master's write and read due to it not having its own inode. Fix the model ASAP. */
static const struct file_ops pty_master_ops = {
    .open = libfs_no_open,
    .getdirent = libfs_no_getdirent,
    .creat = libfs_no_creat,
    .link = libfs_no_link,
    .symlink = libfs_no_symlink,
    .ftruncate = libfs_no_ftruncate,
    .mkdir = libfs_no_mkdir,
    .mknod = libfs_no_mknod,
    .readlink = libfs_no_readlink,
    .unlink = libfs_no_unlink,
    .fallocate = libfs_no_fallocate,
    .on_open = pty_master_on_open,
    .write = ptydevfs_write,
    .read = ptydevfs_read,
    .read_iter = ptydevfs_read_iter,
    .ioctl = pty_ioctl_redir,
    .poll = pty_poll,
};

static const struct file_ops pty_slave_ops = {
    .open = libfs_no_open,
    .getdirent = libfs_no_getdirent,
    .creat = libfs_no_creat,
    .link = libfs_no_link,
    .symlink = libfs_no_symlink,
    .ftruncate = libfs_no_ftruncate,
    .mkdir = libfs_no_mkdir,
    .mknod = libfs_no_mknod,
    .readlink = libfs_no_readlink,
    .unlink = libfs_no_unlink,
    .fallocate = libfs_no_fallocate,
    .on_open = pty_slave_on_open,
    .write = ptydevfs_write,
    .read = ptydevfs_read,
    .read_iter = ptydevfs_read_iter,
    .ioctl = pty_ioctl_redir,
    .poll = pty_poll,
};

static void pty_init(void)
{
    tty_init_pty_dev(&pty_master_ops);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(pty_init);
