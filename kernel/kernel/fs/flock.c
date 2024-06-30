/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/compiler.h>
#include <onyx/file.h>
#include <onyx/flock.h>
#include <onyx/list.h>
#include <onyx/mm/slab.h>
#include <onyx/mutex.h>
#include <onyx/spinlock.h>
#include <onyx/vfs.h>
#include <onyx/wait_queue.h>

#include <uapi/errno.h>

static void remove_lock(struct flock_file_info *finfo, struct inode *ino)
{
    struct flock_info *flck = &ino->i_flock;
    spin_lock(&flck->lock);
    list_remove(&finfo->list_node);

    /* Note: Currently, thundering herd is a problem. However, I don't believe flocks (nor POSIX
     * advisory locks) are contested enough for this to matter. */
    if (list_is_empty(&flck->excl_holders) || list_is_empty(&flck->shared_holders))
        wait_queue_wake_all(&flck->flock_wq);
    spin_unlock(&flck->lock);
}

#define LOCK_OP(op) ((op) & ~LOCK_NB)

static bool may_lock(struct flock_file_info *finfo, struct flock_info *flck)
{
    /* Check if we may hold the lock. If not, possibly bail if LOCK_NB */
    switch (finfo->type)
    {
        case LOCK_EX:
            return list_is_empty(&flck->excl_holders) && list_is_empty(&flck->shared_holders);
        case LOCK_SH:
            return list_is_empty(&flck->excl_holders);
        default:
            UNREACHABLE();
    }
}

static int do_flock(struct file *filp, int op) REQUIRES(filp->f_seeklock)
{
    struct flock_file_info *finfo = filp->f_flock;
    struct inode *ino = filp->f_ino;
    struct flock_info *flck = &ino->i_flock;
    int err = 0;
    if (!finfo)
    {
        /* Bail early if we didn't have a lock */
        if (LOCK_OP(op) == LOCK_UN)
            return 0;
        finfo = kmalloc(sizeof(*finfo), GFP_KERNEL);
        if (!finfo)
            return -ENOLCK;
    }
    else
    {
        /* Check if we hold that same lock already. */
        if (finfo->type == LOCK_OP(op))
            return 0;
        remove_lock(finfo, ino);
        filp->f_flock = NULL;
        if (LOCK_OP(op) == LOCK_UN)
        {
            /* Free and bail. */
            free(finfo);
            return 0;
        }
    }

    finfo->type = LOCK_OP(op);

    spin_lock(&flck->lock);
    if (!may_lock(finfo, flck) && op & LOCK_NB)
    {
        err = -EWOULDBLOCK;
        goto out;
    }

    err = wait_for_event_locked_interruptible(&flck->flock_wq, may_lock(finfo, flck), &flck->lock);
    if (err == 0)
    {
        DCHECK(may_lock(finfo, flck));
        if (LOCK_OP(op) == LOCK_SH)
            list_add_tail(&finfo->list_node, &flck->shared_holders);
        else
            list_add_tail(&finfo->list_node, &flck->excl_holders);
    }

out:
    spin_unlock(&flck->lock);
    if (err)
        kfree(finfo);
    else
        filp->f_flock = finfo;
    return err;
}

#define VALID_FLAGS (LOCK_SH | LOCK_EX | LOCK_UN | LOCK_NB)
int sys_flock(int fd, int op) NO_THREAD_SAFETY_ANALYSIS
{
    int err;
    if (op & ~VALID_FLAGS || !(op & (LOCK_SH | LOCK_EX | LOCK_UN)))
        return -EINVAL;

    struct file *filp = get_file_description(fd);
    if (!filp)
        return -EBADF;

    /* Grab the seek lock. This will serve as our state lock for the
     * fd in this case (so multiple processes can't grab the same lock
     * and cause a race). */
    if ((err = mutex_lock_interruptible(&filp->f_seeklock)) != 0)
        goto out_put;
    err = do_flock(filp, op);
    mutex_unlock(&filp->f_seeklock);
out_put:
    fd_put(filp);
    return err;
}

void flock_release(struct file *filp)
{
    /* Release the file lock, on close */
    struct flock_file_info *finfo = filp->f_flock;
    struct inode *ino = filp->f_ino;
    DCHECK(finfo != NULL);
    remove_lock(finfo, ino);
}
