/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/compiler.h>
#include <onyx/file.h>
#include <onyx/flock.h>
#include <onyx/list.h>
#include <onyx/mm/slab.h>
#include <onyx/mutex.h>
#include <onyx/process.h>
#include <onyx/spinlock.h>
#include <onyx/vfs.h>
#include <onyx/wait_queue.h>

#include <uapi/errno.h>

static void remove_lock(struct flock_file_info *finfo, struct inode *ino)
{
    struct flock_info *flck = inode_to_flock(ino);
    DCHECK(flck);
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

static struct flock_info *flock_get_or_alloc(struct inode *inode)
{
    struct flock_info *flck = inode_to_flock(inode);
    if (likely(flck))
        return flck;
    flck = kmalloc(sizeof(*flck), GFP_KERNEL);
    if (!flck)
        return NULL;
    flock_init(flck);

    if (cmpxchg(&inode->i_flock, (struct flock_info *) NULL, flck) != NULL)
    {
        kfree(flck);
        flck = inode_to_flock(inode);
        DCHECK(flck);
    }

    return flck;
}

static int do_flock(struct file *filp, int op) REQUIRES(filp->f_seeklock)
{
    struct flock_file_info *finfo = filp->f_flock;
    struct inode *ino = filp->f_ino;
    struct flock_info *flck = flock_get_or_alloc(ino);
    int err = 0;

    if (!flck)
        return -ENOMEM;

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

static bool cmd_is_ofd_lock(int cmd)
{
    switch (cmd)
    {
        case F_OFD_GETLK:
        case F_OFD_SETLK:
        case F_OFD_SETLKW:
            return true;
        default:
            return false;
    }
}

static bool flock_validate(int cmd, const struct flock *arg)
{
    if (cmd_is_ofd_lock(cmd))
    {
        if (arg->l_pid != 0)
            return false;
    }

    if (arg->l_type != F_RDLCK && arg->l_type != F_WRLCK && arg->l_type != F_UNLCK)
        return false;
    if (arg->l_whence != SEEK_CUR && arg->l_whence != SEEK_SET && arg->l_whence != SEEK_END)
        return false;
    return true;
}

static int flock_fill_in(int cmd, struct file *filp, struct flock *fl, struct flock_posix_lock *pl)
{
    off_t base = 0;

    pl->flags = (fl->l_type == F_WRLCK ? FLOCK_POSIX_WR : 0) |
                (fl->l_type == F_UNLCK ? FLOCK_POSIX_UNLCK : 0);

    if (cmd_is_ofd_lock(cmd))
    {
        pl->owner.filp = filp;
        pl->flags |= FLOCK_POSIX_OFD;
    }
    else
        pl->owner.pid = get_current_process()->pid_;

    switch (fl->l_whence)
    {
        case SEEK_CUR:
            base = filp->f_seek;
            break;
        case SEEK_END:
            base = filp->f_ino->i_size;
            break;
    }

    if (fl->l_len > 0)
    {
        pl->start = fl->l_start + base;
        pl->end = pl->start + fl->l_len - 1;
    }
    else if (fl->l_len < 0)
    {
        pl->start = fl->l_start + fl->l_len + base;
        pl->end = pl->start + base - 1;
    }
    else if (fl->l_len == 0)
    {
        pl->start = fl->l_start + base;
        pl->end = INT64_MAX;
    }

    if (pl->start < 0)
        return -EINVAL;
    return 0;
}

static inline bool flock_locks_overlap(const struct flock_posix_lock *l1,
                                       const struct flock_posix_lock *l2)
{
    return l1->start <= l2->end && l2->start <= l1->end;
}

static bool flock_locks_same_owner(const struct flock_posix_lock *l1,
                                   const struct flock_posix_lock *l2)
{
    if ((l1->flags & FLOCK_POSIX_OFD) != (l2->flags & FLOCK_POSIX_OFD))
        return false;
    if (l1->flags & FLOCK_POSIX_OFD)
        return l1->owner.filp == l2->owner.filp;
    return l1->owner.pid == l2->owner.pid;
}

static bool flock_locks_conflict(const struct flock_posix_lock *l1,
                                 const struct flock_posix_lock *l2)
{
    /* Check if the ranges overlap */
    if (!flock_locks_overlap(l1, l2))
        return false;
    /* Check if these are both read locks */
    if (!(l1->flags & FLOCK_POSIX_WR) && !(l2->flags & FLOCK_POSIX_WR))
        return false;

    if (l1->flags & FLOCK_POSIX_UNLCK || l2->flags & FLOCK_POSIX_UNLCK)
    {
        /* We strictly do not care if locks conflict, if we're unlocking */
        return false;
    }

    /* Two locks don't conflict (we will change it under F_SETLK) if locked by the same pid, or same
     * file. files conflict with pids and vice-versa. */
    return !flock_locks_same_owner(l1, l2);
}

static int flock_getlock_posix(int cmd, struct file *filp, struct flock *arg)
{
    int err = 0;
    struct flock_info *info = flock_get_or_alloc(filp->f_ino);
    struct flock_posix_lock tmp;

    if (!info)
        return -ENOMEM;

    if (arg->l_type == F_UNLCK)
        return -EINVAL;
    if (flock_fill_in(cmd, filp, arg, &tmp) < 0)
        return -EINVAL;

    spin_lock(&info->lock);

    struct flock_posix_lock *lock;
    list_for_each_entry(lock, &info->posix_locks, list_node)
    {
        /* If these locks conflict and overlap, we found our boy. They do not conflict if two locks
         * are read-mode, or locked by us. */
        if (flock_locks_conflict(&tmp, lock))
        {
            arg->l_whence = SEEK_SET;
            arg->l_start = lock->start;
            arg->l_len = lock->end - lock->start + 1;
            arg->l_type = lock->flags & FLOCK_POSIX_WR ? F_WRLCK : F_RDLCK;
            arg->l_pid = lock->flags & FLOCK_POSIX_OFD ? -1 : lock->owner.pid;
            goto out;
        }
    }

    arg->l_type = F_UNLCK;
out:
    spin_unlock(&info->lock);
    return err;
}

static bool flock_is_ofd(struct flock_posix_lock *pl)
{
    return pl->flags & FLOCK_POSIX_OFD;
}

static int ___flock_setlock_posix(struct file *filp, struct flock_posix_lock *pl)
{
    struct flock_info *info = inode_to_flock(filp->f_ino);
    DCHECK(info);
    struct flock_posix_lock *lock, *next;
    bool seen_read = false, seen_write = false;
    bool pass2 = false;

    /* Go through the list and find conflits. If it's our lock, we can change it. */
    list_for_each_entry(lock, &info->posix_locks, list_node)
    {
        if (flock_locks_conflict(pl, lock))
            return -EAGAIN;
        if (flock_locks_overlap(pl, lock) && flock_locks_same_owner(pl, lock))
        {
            pass2 = true;
            if (lock->start < pl->start && lock->end > pl->end)
            {
                /* This annoying lock requires a split... */
                struct flock_posix_lock *lock2 = kmalloc(sizeof(*lock2), GFP_ATOMIC);
                if (!lock2)
                    return -ENOMEM;
                lock2->flags = lock->flags;
                if (flock_is_ofd(lock2))
                    lock2->owner.filp = lock->owner.filp;
                else
                    lock2->owner.pid = lock->owner.pid;
                lock2->start = pl->start;
                lock2->end = lock->end;
                lock->end = pl->start - 1;
                list_add_tail(&lock2->list_node, &info->posix_locks);
            }
        }
    }

    if (pass2)
    {
        /* Make a second pass through the lock list and change the locks we need to */
        list_for_each_entry_safe(lock, next, &info->posix_locks, list_node)
        {
            if (!flock_locks_overlap(pl, lock) || !flock_locks_same_owner(pl, lock))
                continue;
            /* We should _not_ find a region that contains the new lock in this second pass. */
            DCHECK(!(lock->start < pl->start && lock->end > pl->end));
            if (lock->flags & FLOCK_POSIX_WR)
                seen_write = true;
            else
                seen_read = true;
            /* Case 1: lock region entirely contained by new lock - remove and free */
            if (lock->start >= pl->start && lock->end <= pl->end)
            {
                list_remove(&lock->list_node);
                kfree(lock);
            }
            else
            {
                /* Case 2: Lock region isn't entirely contained by new lock - adjust lock regions */
                if (pl->start > lock->start)
                    lock->end = pl->start - 1;
                else if (pl->end < lock->end)
                    lock->start = pl->end + 1;
                else
                    WARN_ON(1);
            }
        }
    }

    if (!(pl->flags & FLOCK_POSIX_UNLCK))
        list_add_tail(&pl->list_node, &info->posix_locks);
    else
    {
        /* TODO: Do something to avoid thundering herd? Separate wait queues? */
        (void) seen_read;
        (void) seen_write;
        wait_queue_wake_all(&info->flock_wq);
    }

    return 0;
}

static int __flock_setlock_posix(struct file *filp, struct flock_posix_lock *pl)
{
    struct flock_info *info = inode_to_flock(filp->f_ino);
    int err;

    spin_lock(&info->lock);
    err = ___flock_setlock_posix(filp, pl);
    spin_unlock(&info->lock);
    return err;
}

static int flock_setlock_posix(int cmd, struct file *filp, struct flock *f)
{
    int err;
    struct flock_posix_lock *pl = kmalloc(sizeof(*pl), GFP_KERNEL);
    if (!pl)
        return -ENOMEM;

    if (flock_fill_in(cmd, filp, f, pl) < 0)
    {
        kfree(pl);
        return -EINVAL;
    }

    err = __flock_setlock_posix(filp, pl);
    if (err < 0)
        kfree(pl);

    return err;
}

static int flock_unlock_posix(int cmd, struct file *filp, struct flock *f)
{
    struct flock_posix_lock tmp;
    if (flock_fill_in(cmd, filp, f, &tmp) < 0)
        return -EINVAL;

    __flock_setlock_posix(filp, &tmp);
    return 0;
}

static int flock_setlockw_posix(int cmd, struct file *filp, struct flock *f,
                                bool has_seek) NO_THREAD_SAFETY_ANALYSIS
{
    int err;
    struct flock_info *info = inode_to_flock(filp->f_ino);
    struct flock_posix_lock *pl = kmalloc(sizeof(*pl), GFP_KERNEL);
    if (!pl)
        return -ENOMEM;

    DCHECK(info);

    if (flock_fill_in(cmd, filp, f, pl) < 0)
    {
        kfree(pl);
        return -EINVAL;
    }

    if (has_seek)
        mutex_unlock(&filp->f_seeklock);

    spin_lock(&info->lock);
    err = wait_for_event_locked_interruptible(&info->flock_wq,
                                              ___flock_setlock_posix(filp, pl) == 0, &info->lock);
    spin_unlock(&info->lock);

    if (has_seek)
        mutex_lock(&filp->f_seeklock);

    if (err)
        kfree(pl);
    return err;
}

int flock_do_posix(struct file *filp, int cmd, struct flock *arg,
                   bool has_seek) NO_THREAD_SAFETY_ANALYSIS
{
    struct flock f;
    if (copy_from_user(&f, arg, sizeof(f)))
        return -EFAULT;

    if (!flock_validate(cmd, &f))
        return -EINVAL;

    /* Make sure we have flock info for the upcoming call */
    if (!flock_get_or_alloc(filp->f_ino))
        return -ENOMEM;

    switch (cmd)
    {
        case F_OFD_GETLK:
        case F_GETLK: {
            int err = flock_getlock_posix(cmd, filp, &f);
            if (err)
                return err;
            return copy_to_user(arg, &f, sizeof(struct flock)) ? -EFAULT : 0;
        }

        case F_OFD_SETLK:
        case F_SETLK:
            if (f.l_type == F_UNLCK)
                return flock_unlock_posix(cmd, filp, &f);
            return flock_setlock_posix(cmd, filp, &f);

        case F_OFD_SETLKW:
        case F_SETLKW:
            return flock_setlockw_posix(cmd, filp, &f, has_seek);
    }

    /* What? */
    DCHECK(0);
    return -ENOTTY;
}

void flock_remove_ofd(struct file *filp)
{
    struct flock_posix_lock *lock, *next;
    bool unlocked = false;
    struct flock_info *info = inode_to_flock(filp->f_ino);
    if (likely(!info || list_is_empty(&info->posix_locks)))
        return;

    spin_lock(&info->lock);

    list_for_each_entry_safe(lock, next, &info->posix_locks, list_node)
    {
        if (lock->flags & FLOCK_POSIX_OFD && lock->owner.filp == filp)
        {
            list_remove(&lock->list_node);
            kfree(lock);
            unlocked = true;
        }
    }

    if (unlocked)
        wait_queue_wake_all(&info->flock_wq);
    spin_unlock(&info->lock);
}

void flock_remove_posix(struct file *filp)
{
    struct flock_posix_lock *lock, *next;
    bool unlocked = false;
    struct flock_info *info = inode_to_flock(filp->f_ino);
    if (likely(!info || list_is_empty(&info->posix_locks)))
        return;

    spin_lock(&info->lock);

    list_for_each_entry_safe(lock, next, &info->posix_locks, list_node)
    {
        if (!(lock->flags & FLOCK_POSIX_OFD) && lock->owner.pid == get_current_process()->pid_)
        {
            list_remove(&lock->list_node);
            kfree(lock);
            unlocked = true;
        }
    }

    if (unlocked)
        wait_queue_wake_all(&info->flock_wq);
    spin_unlock(&info->lock);
}
