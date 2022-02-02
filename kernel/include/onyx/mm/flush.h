/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_MM_FLUSH_H
#define _ONYX_MM_FLUSH_H

#include <onyx/list.h>
#include <onyx/mutex.h>
#include <onyx/semaphore.h>
#include <onyx/spinlock.h>
#include <onyx/vm.h>

/* TODO: This file started as mm specific but it's quite fs now, no? */

struct inode;

struct flush_object;
/* Implemented by users of the flush subsystem */
struct flush_ops
{
    ssize_t (*flush)(struct flush_object *fmd);
    bool (*is_dirty)(struct flush_object *fmd);
    void (*set_dirty)(bool value, struct flush_object *fmd);
};

struct flush_object
{
    struct list_head dirty_list;
    void *blk_list;
    const struct flush_ops *ops;
};

/* Keep C APIs here */

void flush_init(void);
void flush_add_buf(struct flush_object *blk);
void flush_remove_buf(struct flush_object *blk);
void flush_add_inode(struct inode *ino);
void flush_remove_inode(struct inode *ino);
ssize_t flush_sync_one(struct flush_object *obj);
void flush_do_sync(void);

#ifdef __cplusplus

#include <onyx/atomic.hpp>

namespace flush
{

class flush_dev
{
private:
    /* Each flush dev has a list of dirty bufs that need flushing. */
    struct list_head dirty_bufs;
    struct list_head dirty_inodes;
    atomic<unsigned long> block_load;
    struct mutex __lock;
    /* Each flush dev also is associated with a thread that runs every x seconds */
    struct thread *thread;
    struct semaphore thread_sem;

public:
    static constexpr unsigned long wb_run_delta_ms = 10000;
    constexpr flush_dev()
        : dirty_bufs{}, dirty_inodes{}, block_load{0}, __lock{}, thread{}, thread_sem{}
    {
        mutex_init(&__lock);
        INIT_LIST_HEAD(&dirty_bufs);
        INIT_LIST_HEAD(&dirty_inodes);
    }

    ~flush_dev()
    {
    }

    unsigned long get_load()
    {
        return block_load;
    }

    void lock()
    {
        mutex_lock(&__lock);
    }
    void unlock()
    {
        mutex_unlock(&__lock);
    }
    bool called_from_sync();

    void init();
    void run();
    bool add_buf(struct flush_object *buf);
    void remove_buf(struct flush_object *buf);
    void add_inode(struct inode *ino);
    void remove_inode(struct inode *ino);
    void sync();
    ssize_t sync_one(struct flush_object *obj);
};

}; // namespace flush

#endif
#endif
