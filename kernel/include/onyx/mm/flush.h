/*
 * Copyright (c) 2019 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_MM_WRITEBACK_H
#define _ONYX_MM_WRITEBACK_H

#include <onyx/list.h>
#include <onyx/mutex.h>
#include <onyx/process.h>
#include <onyx/semaphore.h>
#include <onyx/spinlock.h>
#include <onyx/vm.h>

struct inode;
struct blockdev;

/* Keep C APIs here */

void flush_init(void);
void flush_add_inode(struct inode *ino);
void flush_remove_inode(struct inode *ino);
void flush_do_sync(void);

#define WB_FLAG_SYNC (1 << 0)

void balance_dirty_pages(struct vm_object *obj);

static inline void balance_dirty_pages_ratelimit(struct vm_object *vmobj)
{
    struct process *curr = get_current_process();
    if (!curr || curr->nr_dirtied >= curr->nr_dirtied_pause)
        balance_dirty_pages(vmobj);
}

#ifdef __cplusplus

#include <onyx/atomic.hpp>

#define WB_FLAG_HAS_IO         (1 << 0)
#define WB_FLAG_DELAYED_QUEUED (1 << 1)

namespace flush
{

class writeback_dev
{
private:
    /* Each writeback dev has a list of dirty inodes that need flushing. */
    struct list_head dirty_inodes;
    struct spinlock __lock;
    unsigned int wb_flags;
    /* Each flush dev also is associated with a thread that runs every x seconds */
    struct thread *thread;
    struct clockevent delayed_wake;
    struct blockdev *bdev;
    struct list_head wbdev_list_node;

public:
    writeback_dev(struct blockdev *bdev) : dirty_inodes{}, thread{}, bdev{bdev}
    {
        spinlock_init(&__lock);
        INIT_LIST_HEAD(&dirty_inodes);
        wb_flags = 0;
        delayed_wake.priv = this;
        delayed_wake.callback = [](struct clockevent *ev) {
            writeback_dev *wbdev = (writeback_dev *) ev->priv;

            wbdev->lock();
            wbdev->wb_flags &= ~WB_FLAG_DELAYED_QUEUED;
            wbdev->wake();
            wbdev->unlock();
        };
    }

    ~writeback_dev() = default;

    void lock()
    {
        spin_lock(&__lock);
    }

    void unlock()
    {
        spin_unlock(&__lock);
    }

    void wake()
    {
        /* This pairs with the implicit memory barrier in writeback_dev::run() */
        thread_wake_up(thread);
    }

    void wake_delayed();
    void init();
    void run();
    void add_inode(struct inode *ino);
    void remove_inode(struct inode *ino);
    void sync(unsigned int flags);
    void end_inode_writeback(struct inode *ino);

    static writeback_dev *from_list_head(struct list_head *l)
    {
        return container_of(l, writeback_dev, wbdev_list_node);
    }
};

}; // namespace flush

#endif
#endif
