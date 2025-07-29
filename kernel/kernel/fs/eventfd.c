/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/anon_inode.h>
#include <onyx/file.h>
#include <onyx/mm/slab.h>
#include <onyx/poll.h>
#include <onyx/wait_queue.h>

#include <uapi/eventfd.h>

struct eventfd
{
    struct wait_queue wq;
    u64 val;
    int flags;
};

static ssize_t eventfd_read_iter(struct file *filp, size_t offset, struct iovec_iter *iter,
                                 unsigned int flags)
{
    struct eventfd *ev = filp->private_data;
    u64 val;
    ssize_t err;

    if (iter->bytes != sizeof(u64))
        return -EINVAL;

    spin_lock(&ev->wq.lock);

    if (unlikely(ev->val == 0))
    {
        if (filp->f_flags & O_NONBLOCK)
        {
            err = -EAGAIN;
            goto err;
        }

        err = wait_for_event_wqlocked_interruptible(&ev->wq, ev->val > 0);
        if (err)
            goto err;
    }

    val = ev->val;

    if (ev->flags & EFD_SEMAPHORE)
    {
        val = 1;
        ev->val--;
    }
    else
        ev->val = 0;

    /* Wake writers (TODO: could be smarter about this) */
    __wait_queue_wake(&ev->wq, 0, NULL, ULONG_MAX);
    spin_unlock(&ev->wq.lock);

    return copy_to_iter(iter, &val, sizeof(val));
err:
    spin_unlock(&ev->wq.lock);
    return err;
}

static ssize_t eventfd_write_iter(struct file *filp, size_t offset, struct iovec_iter *iter,
                                  unsigned int flags)
{
    struct eventfd *ev = filp->private_data;
    ssize_t err;
    u64 to_add;

    if (iter->bytes != sizeof(to_add))
        return -EINVAL;

    if (copy_from_iter(iter, &to_add, sizeof(to_add)) < 0)
        return -EFAULT;

    if (to_add == UINT64_MAX)
        return -EINVAL;

    spin_lock(&ev->wq.lock);
    if (UINT64_MAX - ev->val <= to_add)
    {
        if (filp->f_flags & O_NONBLOCK)
        {
            err = -EAGAIN;
            goto out;
        }

        err = wait_for_event_wqlocked_interruptible(&ev->wq, UINT64_MAX - ev->val > to_add);
        if (err)
            goto out;
    }

    err = sizeof(u64);
    ev->val += to_add;
    /* Wake readers */
    __wait_queue_wake(&ev->wq, 0, NULL, ULONG_MAX);
out:
    spin_unlock(&ev->wq.lock);
    return err;
}

static short eventfd_poll(void *poll_file, short events, struct file *filp)
{
    short avail = 0;
    struct eventfd *ev = filp->private_data;
    u64 val;

    /* Add ourselves to the waitqueue before reading the value. This is both faster (doesn't require
     * us to take the lock), and significantly easier to deal with. poll code checks if we indeed
     * got signalled before sleeping, and the memory barriers involved in sleep/wakeup make it all
     * safe. */
    poll_wait_helper(poll_file, &ev->wq);

    val = READ_ONCE(ev->val);

    if (val > 0)
        avail |= POLLIN;

    if (val < UINT64_MAX - 1)
        avail |= POLLOUT;

    return avail & events;
}

static void eventfd_release(struct file *filp)
{
    kfree(filp->private_data);
}

static const struct file_ops eventfd_ops = {
    .write_iter = eventfd_write_iter,
    .read_iter = eventfd_read_iter,
    .poll = eventfd_poll,
    .release = eventfd_release,
};

#define EFD_VALID_FLAGS (EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK)

int sys_eventfd2(unsigned int initval, int flags)
{
    struct eventfd *ev;
    struct file *filp;
    int fd;

    if (flags & ~EFD_VALID_FLAGS)
        return -EINVAL;

    ev = kmalloc(sizeof(*ev), GFP_KERNEL);
    if (!ev)
        return -ENOMEM;

    ev->val = initval;
    init_wait_queue_head(&ev->wq);
    ev->flags = flags;

    filp = anon_inode_open(S_IFREG, &eventfd_ops, "[eventfd]");
    if (!filp)
    {
        kfree(ev);
        return -ENOMEM;
    }

    filp->private_data = ev;
    fd = open_with_vnode(filp, O_RDWR | (flags & (EFD_NONBLOCK | EFD_CLOEXEC)));
    if (fd < 0)
    {
        fd_put(filp);
        return fd;
    }

    return fd;
}

int sys_eventfd(unsigned int initval)
{
    return sys_eventfd2(initval, 0);
}
