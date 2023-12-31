/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_MM_WRITEBACK_H
#define _ONYX_MM_WRITEBACK_H

#include <onyx/list.h>
#include <onyx/mutex.h>
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

#ifdef __cplusplus

#include <onyx/atomic.hpp>

namespace flush
{

class writeback_dev
{
private:
    /* Each writeback dev has a list of dirty inodes that need flushing. */
    struct list_head dirty_inodes;
    struct spinlock __lock;
    /* Each flush dev also is associated with a thread that runs every x seconds */
    struct thread *thread;
    struct semaphore thread_sem;
    struct blockdev *bdev;
    struct list_head wbdev_list_node;

public:
    constexpr writeback_dev(struct blockdev *bdev)
        : dirty_inodes{}, thread{}, thread_sem{}, bdev{bdev}
    {
        INIT_LIST_HEAD(&dirty_inodes);
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
