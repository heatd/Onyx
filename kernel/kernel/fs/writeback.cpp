/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <stdio.h>

#include <onyx/block.h>
#include <onyx/filemap.h>
#include <onyx/gen/trace_writeback.h>
#include <onyx/mm/flush.h>
#include <onyx/scheduler.h>
#include <onyx/vfs.h>

/* Brief comment on lock ordering in this file:
 * Lock ordering goes like this:
 *  wbdev -> inode
 * Any attempt to grab the wbdev with the inode lock must drop the inode lock beforehand.
 */

static void flush_thr_init(void *arg);

namespace flush
{

struct rwlock wbdev_list_lock;
DEFINE_LIST(wbdev_list);

/* Run the writeback thread every 10s, if needed */
static constexpr unsigned long wb_run_delta_ms = 10000;

void writeback_dev::init()
{
    {
        scoped_rwlock<rw_lock::write> g{wbdev_list_lock};
        list_add_tail(&wbdev_list_node, &wbdev_list);
    }

    thread = sched_create_thread(flush_thr_init, THREAD_KERNEL, (void *) this);
    assert(thread != nullptr);
    sched_start_thread(thread);
}

static int writeback_inode(struct inode *inode, unsigned int sync_flags)
{
    const ino_t inum = inode->i_inode;
    const dev_t dev = inode->i_dev;
    struct writepages_info winfo;
    winfo.start = 0;
    winfo.end = ULONG_MAX;
    winfo.flags = 0;

    if (sync_flags & WB_FLAG_SYNC)
        winfo.flags |= WRITEPAGES_SYNC;

    CHECK(inode->i_fops->writepages != nullptr);
    unsigned int flags;

    DCHECK(inode->i_flags & I_WRITEBACK);

    {
        scoped_lock g{inode->i_lock};
        flags = inode->i_flags & I_DIRTYALL;
        // Note: We clear I_DIRTY here. Any posterior dirty will re-dirty the inode.
        inode->i_flags &= ~I_DIRTY;
    }

    if (flags & I_DATADIRTY)
    {
        int st;
        if (sync_flags & WB_FLAG_SYNC)
            st = inode->i_fops->fsyncdata(inode, &winfo);
        else
            st = inode->i_fops->writepages(inode, &winfo);
        if (st < 0)
            return st;
    }

    if (flags & I_DIRTY)
    {
        TRACE_EVENT_DURATION(wb_write_inode, inum, dev);
        int st = 0;
        if (inode->i_sb && inode->i_sb->flush_inode)
            st = inode->i_sb->flush_inode(inode, sync_flags & WB_FLAG_SYNC);
        if (st < 0)
            return st;
    }

    {
        scoped_lock g{inode->i_lock};
        // Note: we cleared I_DIRTY before, so don't do it again; that would lead to data loss.
        inode->i_flags &= (~flags | I_DIRTY);

        /* Re-dirty if FILEMAP_MARK_DIRTY is set */
        scoped_lock g2{inode->i_pages->page_lock};
        if (inode->i_pages->vm_pages.mark_is_set(FILEMAP_MARK_DIRTY))
            inode->i_flags |= I_DATADIRTY;
        // Ok, now we have the proper I_DIRTY flags set. end_inode_writeback will deal with
        // requeuing it if need be.
    }

    return 0;
}

void writeback_dev::end_inode_writeback(struct inode *ino)
{
    lock();
    spin_lock(&ino->i_lock);
    DCHECK(ino->i_flags & I_WRITEBACK);
    /* Unset I_WRITEBACK and re-queue the inode if need be */
    ino->i_flags &= ~I_WRITEBACK;

    if (ino->i_flags & I_DIRTYALL)
        add_inode(ino);
    spin_unlock(&ino->i_lock);
    wake_address(ino);
    unlock();
}

void writeback_dev::sync(unsigned int flags)
{
    DEFINE_LIST(io_list);
    TRACE_EVENT_DURATION(wb_wbdev_run);
    lock();

    /* Go through the dirty inodes list, set I_WRITEBACK and then splice the list into io_list.
     * We'll then work with that *without the lock*. Dirtying inode code will avoid
     * putting I_WRITEBACK inodes into the dirty_inodes list, which saves our bacon here.
     */
    list_for_every (&dirty_inodes)
    {
        struct inode *ino = container_of(l, struct inode, i_dirty_inode_node);
        scoped_lock g{ino->i_lock};
        DCHECK(!(ino->i_flags & I_WRITEBACK));
        DCHECK(ino->i_flags & (I_DIRTY | I_DATADIRTY));
        ino->i_flags |= I_WRITEBACK;
    }

    list_move(&io_list, &dirty_inodes);
    DCHECK(list_is_empty(&dirty_inodes));
    /* dirty_inodes is now empty, all inodes are I_WRITEBACK. I_WRITEBACK inodes will not go away.
     */
    unlock();

    /* Now do writeback */
    list_for_every_safe (&io_list)
    {
        struct inode *ino = container_of(l, struct inode, i_dirty_inode_node);
        DCHECK(ino->i_flags & I_WRITEBACK);

        list_remove(&ino->i_dirty_inode_node);
        writeback_inode(ino, flags);
        end_inode_writeback(ino);
    }
}

void writeback_dev::run()
{
    trace_wb_wbdev_create();
    while (true)
    {
        while (!list_is_empty(&dirty_inodes))
        {
            sched_sleep_ms(wb_run_delta_ms);
            sync(0);
        }

        sem_wait(&thread_sem);
    }
}

void writeback_dev::add_inode(struct inode *ino)
{
    DCHECK(!(ino->i_flags & I_WRITEBACK));
    bool should_wake = list_is_empty(&dirty_inodes);
    list_add_tail(&ino->i_dirty_inode_node, &dirty_inodes);
    if (should_wake)
        sem_signal(&thread_sem);
}

void writeback_dev::remove_inode(struct inode *ino)
{
    list_remove(&ino->i_dirty_inode_node);
}

} // namespace flush

void flush_thr_init(void *arg)
{
    flush::writeback_dev *b = reinterpret_cast<flush::writeback_dev *>(arg);
    b->run();
}

void flush_init()
{
}

void flush_add_inode(struct inode *ino)
{
    // HACK! the inode - file - vm_object scheme we have is currently so screwed up, that some
    // inodes can end up with no i_sb. This is bad. Let's ignore this problem for the time being.
    // One cannot writeback those inodes. Oh no! They were not supposed to be written back anyway.
    if (!ino->i_sb)
        return;
    auto dev = bdev_get_wbdev(ino);
    ino->i_flush_dev = dev;
    dev->add_inode(ino);
}

void flush_remove_inode(struct inode *ino)
{
    // HACK! See flush_add_inode()'s comment.
    if (!ino->i_sb)
        return;
    auto dev = bdev_get_wbdev(ino);
    dev->remove_inode(ino);
    ino->i_flush_dev = nullptr;
}

void flush_do_sync()
{
    /* TODO: This sub-optimal and will need to be changed when writeback becomes async */
    scoped_rwlock<rw_lock::read> g{flush::wbdev_list_lock};
    list_for_every (&flush::wbdev_list)
    {
        flush::writeback_dev *wbdev = flush::writeback_dev::from_list_head(l);
        wbdev->sync(WB_FLAG_SYNC);
    }
}

enum d_walk_ret
{
    D_WALK_CONTINUE,
    D_WALK_QUIT,
    D_WALK_NORETRY,
    D_WALK_SKIP,
    __D_WALK_RESTART
};

void d_walk(struct dentry *parent, void *data,
            enum d_walk_ret (*enter)(void *data, struct dentry *));

void kasan_check_memory(unsigned long addr, size_t size, bool write);

static enum d_walk_ret enter(void *data, struct dentry *dentry)
{
    kasan_check_memory((unsigned long) dentry, sizeof(struct dentry), false);
    pr_info("dentry %s refs %lx\n", dentry->d_name, dentry->d_ref);
    (*((int *) data))++;
    return D_WALK_CONTINUE;
}

void dentry_shrink_subtree(struct dentry *dentry);

void sys_sync()
{
    flush_do_sync();
    struct path p = get_filesystem_root();
    int dentries = 0;
    d_walk(p.dentry, &dentries, enter);
    pr_info("seen %d dentries\n", dentries);
    DCHECK(!sched_is_preemption_disabled());
    dentry_shrink_subtree(p.dentry);
    DCHECK(!sched_is_preemption_disabled());
    dentries = 0;
    d_walk(p.dentry, &dentries, enter);
    pr_info("seen %d dentries\n", dentries);
    DCHECK(!sched_is_preemption_disabled());
}
