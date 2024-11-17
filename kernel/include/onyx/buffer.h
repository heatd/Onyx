/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_BUFFER_H
#define _ONYX_BUFFER_H

#include <onyx/bdev_base_types.h>
#include <onyx/list.h>
#include <onyx/mm/flush.h>
#include <onyx/page.h>

__BEGIN_CDECLS

/* block_buf represents a filesystem block(works kind of like a buffer_head in linux).
 * It keeps information like whether the block is dirty, the page it's stored on, the offset, etc.
 * It's supposed to be used by filesystems only, for metadata.
 */

struct vm_object;

struct block_buf
{
    /* This block's refcount */
    unsigned long refc;
    /* The page it's stored on */
    struct page *this_page;
    /* This represents the next block_buf within the page */
    struct block_buf *next;
    /* The offset within the page */
    unsigned int page_off;
    /* Various flags - see below */
    unsigned int flags;
    /* The corresponding block device */
    struct blockdev *dev;
    /* The block number */
    sector_t block_nr;
    /* The block size */
    unsigned int block_size;
    struct spinlock pagestate_lock;
    struct list_head assoc_buffers_node;
    struct vm_object *assoc_buffers_obj;
};

#define BLOCKBUF_FLAG_DIRTY     (1 << 0)
#define BLOCKBUF_FLAG_WRITEBACK (1 << 1)
#define BLOCKBUF_FLAG_UPTODATE  (1 << 2)
#define BLOCKBUF_FLAG_AREAD     (1 << 3)
#define BLOCKBUF_FLAG_HOLE      (1 << 4)

static inline bool bb_test_and_set(struct block_buf *buf, unsigned int flag)
{
    unsigned int old;
    do
    {
        old = __atomic_load_n(&buf->flags, __ATOMIC_ACQUIRE);
        if (old & flag)
            return false;
    } while (!__atomic_compare_exchange_n(&buf->flags, &old, old | flag, false, __ATOMIC_RELEASE,
                                          __ATOMIC_RELAXED));
    return true;
}

static inline bool bb_test_and_clear(struct block_buf *buf, unsigned int flag)
{
    return __atomic_fetch_and(&buf->flags, ~flag, __ATOMIC_RELEASE) & flag;
}

static inline void bb_clear_flag(struct block_buf *buf, unsigned int flag)
{
    __atomic_and_fetch(&buf->flags, ~flag, __ATOMIC_RELEASE);
}

static inline bool bb_test_flag(struct block_buf *buf, unsigned int flag)
{
    return __atomic_load_n(&buf->flags, __ATOMIC_RELAXED) & flag;
}

bool page_has_writeback_bufs(struct page *p);

#define MAX_BLOCK_SIZE PAGE_SIZE

struct superblock;

struct block_buf *page_add_blockbuf(struct page *page, unsigned int page_off);
struct block_buf *sb_read_block(const struct superblock *sb, unsigned long block);
void block_buf_free(struct block_buf *buf);
void block_buf_sync(struct block_buf *buf);
void block_buf_dirty(struct block_buf *buf);
struct block_buf *block_buf_from_page(struct page *p);
void page_destroy_block_bufs(struct page *page);

static inline void block_buf_get(struct block_buf *buf)
{
    __atomic_add_fetch(&buf->refc, 1, __ATOMIC_RELAXED);
    page_ref(buf->this_page);
}

static inline void block_buf_put(struct block_buf *buf)
{
    unsigned long result = __atomic_sub_fetch(&buf->refc, 1, __ATOMIC_RELAXED);
    page_unref(buf->this_page);

    if (result == 0)
        block_buf_free(buf);
}

static inline void *block_buf_data(struct block_buf *b)
{
    return (void *) (((unsigned long) PAGE_TO_VIRT(b->this_page)) + b->page_off);
}

/**
 * @brief Associate a block_buf with a vm_object
 * This is used for e.g indirect blocks that want to be written back
 * when doing fsync. The vm_object does *not* need to be the block device's.
 *
 * @param buf Block buf
 * @param object Object
 */
void block_buf_associate(struct block_buf *buf, struct vm_object *object);

/**
 * @brief Sync all the associated buffers to this vm_object
 *
 * @param object VM object (of probably an fs's inode)
 */
void block_buf_sync_assoc(struct vm_object *object);

/**
 * @brief Dirty a block buffer and associate it with an inode
 * The association will allow us to write this buffer back when syncing
 * the inode's data.
 *
 * @param buf Buffer to dirty
 * @param inode Inode to add it to
 */
void block_buf_dirty_inode(struct block_buf *buf, struct inode *inode);

/**
 * @brief Forget a block_buf's inode
 * This will remove it from the assoc list
 *
 * @param buf Buffer
 */
void block_buf_forget_inode(struct block_buf *buf);

/**
 * @brief Tear down a vm object's assoc list
 *
 * @param object Object to tear down
 */
void block_buf_tear_down_assoc(struct vm_object *object);

void page_remove_block_buf(struct page *page, size_t offset, size_t end);

void buffer_free_page(struct vm_object *vmo, struct page *page);

struct block_buf *bdev_read_block(struct blockdev *bdev, unsigned long block);

__END_CDECLS

#ifdef __cplusplus

class auto_block_buf
{
private:
    block_buf *buf;

public:
    auto_block_buf() : buf{nullptr}
    {
    }
    auto_block_buf(block_buf *b) : buf{b}
    {
    }

    void unref() const
    {
        block_buf_put(buf);
    }

    void ref() const
    {
        block_buf_get(buf);
    }

    block_buf *release()
    {
        auto ret = buf;
        buf = nullptr;
        return ret;
    }

    void reset(block_buf *b)
    {
        if (buf)
            unref();
        buf = b;
    }

    auto_block_buf &operator=(auto_block_buf &&rhs)
    {
        if (this != &rhs)
            reset(rhs.release());
        return *this;
    }

    auto_block_buf(auto_block_buf &&rhs)
    {
        if (this != &rhs)
        {
            buf = nullptr;
            reset(rhs.release());
        }
    }

    auto_block_buf &operator=(const auto_block_buf &rhs)
    {
        auto b = rhs.buf;

        if (this == &rhs)
            return *this;

        if (b)
            block_buf_get(b);

        reset(b);

        return *this;
    }

    auto_block_buf(const auto_block_buf &rhs)
    {
        auto b = rhs.buf;

        if (this == &rhs)
            return;

        if (b)
            block_buf_get(b);

        reset(b);
    }

    ~auto_block_buf()
    {
        if (buf)
            unref();
    }

    operator bool() const
    {
        return buf != nullptr;
    }

    operator block_buf *() const
    {
        return buf;
    }
};

class buf_dirty_trigger
{
private:
    auto_block_buf &buf;
    struct inode *inode{nullptr};
    bool dont_dirty;

    void do_dirty()
    {
        if (inode)
            block_buf_dirty_inode(buf, inode);
        else
            block_buf_dirty(buf);
    }

public:
    buf_dirty_trigger(auto_block_buf &b, struct inode *inode = nullptr)
        : buf{b}, inode{inode}, dont_dirty{false}
    {
    }

    ~buf_dirty_trigger()
    {
        if (!dont_dirty)
            do_dirty();
    }

    void explicit_dirty()
    {
        do_dirty();
        dont_dirty = true;
    }

    void do_not_dirty()
    {
        dont_dirty = true;
    }
};

#endif

#endif
