/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/block.h>
#include <onyx/block/io-queue.h>
#include <onyx/buffer.h>
#include <onyx/filemap.h>
#include <onyx/init.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/page_iov.h>
#include <onyx/rwlock.h>
#include <onyx/softirq.h>

#include <uapi/fcntl.h>

static struct rwlock dev_list_lock;
static struct list_head dev_list = LIST_HEAD_INIT(dev_list);

/*
 * Function: struct blockdev *blkdev_search(const char *name);
 * Description: Search for 'name' on the linked list
 * Return value: Returns a valid block device on success, NULL on error. Sets errno properly.
 * errno values: EINVAL - invalid argument;
 */
struct blockdev *blkdev_search(const char *name)
{
    assert(name != nullptr);

    rw_lock_read(&dev_list_lock);

    list_for_every (&dev_list)
    {
        struct blockdev *blk = container_of(l, struct blockdev, block_dev_head);
        if (blk->name == name)
        {
            rw_unlock_read(&dev_list_lock);
            return blk;
        }
    }

    rw_unlock_read(&dev_list_lock);

    return NULL;
}

unsigned int blkdev_ioctl(int request, void *argp, struct file *f)
{
    auto d = (blockdev *) f->f_ino->i_helper;

    (void) d;
    switch (request)
    {
        default:
            return -EINVAL;
    }
}

struct superblock *bdev_sb;

/**
 * @brief blockdevfs inode
 *
 */
struct block_inode
{
    struct inode b_inode;
    flush::writeback_dev *b_wbdev;

    /**
     * @brief Create a new blockdev inode
     *
     * @arg dev Block device
     * @return Properly set up blockdev inode, or NULL
     */
    static unique_ptr<block_inode> create(const struct blockdev *dev, flush::writeback_dev *wbdev);
};

/**
 * @brief Create a new blockdev inode
 *
 * @arg dev Block device
 * @return Properly set up blockdev inode, or NULL
 */
unique_ptr<block_inode> block_inode::create(const struct blockdev *dev, flush::writeback_dev *wbdev)
{
    unique_ptr<block_inode> ino = make_unique<block_inode>();
    if (!ino)
        return nullptr;
    auto &inode = ino->b_inode;

    if (inode_init(&inode, true) < 0)
        return nullptr;
    inode.i_dev = dev->dev->dev();
    inode.i_sb = bdev_sb;
    ino->b_wbdev = wbdev;

    superblock_add_inode(bdev_sb, &inode);
    return ino;
}

/**
 * @brief Set up a pseudo-fs (that we sometimes call blockdevfs) for caching and dirtying
 *
 */
__init static void bdev_setup_fs()
{
    bdev_sb = new superblock;
    CHECK(bdev_sb);

    superblock_init(bdev_sb);
}

extern struct file_ops buffer_ops;

int blkdev_init(struct blockdev *blk)
{
    rw_lock_write(&dev_list_lock);

    list_add_tail(&blk->block_dev_head, &dev_list);

    rw_unlock_write(&dev_list_lock);

    auto ex = dev_register_blockdevs(0, 1, 0, &buffer_ops, cul::string{blk->name});

    if (ex.has_error())
    {
        return ex.error();
    }

    auto dev = ex.value();

    dev->private_ = blk;
    dev->show(BLOCK_DEVICE_PERMISSIONS);

    blk->dev = dev;

    blk->wbdev = make_unique<flush::writeback_dev>(blk);
    if (!blk->wbdev)
    {
        dev_unregister_dev(dev, true);
        return -ENOMEM;
    }

    blk->wbdev->init();

    auto ino = block_inode::create(blk, blk->wbdev.get());
    if (!ino)
    {
        dev_unregister_dev(dev, true);
        return -ENOMEM;
    }

    ino->b_inode.i_fops = &buffer_ops;
    ino->b_inode.i_helper = (void *) blk;
    blk->b_ino = (struct inode *) ino.release();

    if (!blkdev_is_partition(blk))
        partition_setup_disk(blk);

    return 0;
}

/*
 * Function: int blkdev_flush(struct blockdev *dev);
 * Description: Flushes storage device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; EIO - operation not supported on storage device 'dev'
 */
int blkdev_flush(struct blockdev *dev)
{
    if (blkdev_is_partition(dev))
        return blkdev_flush(dev->actual_blockdev);
    if (!dev->flush)
        return errno = ENOSYS, -1;

    return dev->flush(dev);
}
/*
 * Function: int blkdev_power(int op, struct blockdev *dev);
 * Description: Performs power management operation 'op' on device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; EIO - operation not supported on storage device 'dev'
 */
int blkdev_power(int op, struct blockdev *dev)
{
    if (blkdev_is_partition(dev))
        return blkdev_power(op, dev->actual_blockdev);
    if (!dev->power)
        return errno = EIO, -1;

    return dev->power(op, dev);
}

int bio_submit_request(struct blockdev *dev, struct bio_req *req)
{
    if (unlikely(dev->submit_request == nullptr))
        return -EIO;

    return dev->submit_request(dev, req);
}

static void bio_submit_sync_end_io(struct bio_req *req)
{
    wake_address(req);
}

/**
 * @brief Submit a bio_req and wait for it to end
 *
 * @param dev Block device
 * @param req Request
 * @return errno-like result of the bio_req
 */
int bio_submit_req_wait(struct blockdev *dev, struct bio_req *req)
{
    DCHECK(req->b_private == nullptr);
    DCHECK(req->b_end_io == nullptr);

    int st = bio_submit_request(dev, req);
    if (st < 0)
        return st;
    req->b_end_io = bio_submit_sync_end_io;

    wait_for(
        req,
        [](void *_req) -> bool {
            struct bio_req *req_ = (struct bio_req *) _req;
            return req_->flags & BIO_REQ_DONE;
        },
        WAIT_FOR_FOREVER, 0);
    if (req->flags & (BIO_REQ_EIO | BIO_REQ_NOT_SUPP))
        return -EIO;
    return 0;
}

atomic<unsigned int> next_scsi_dev_num = 0;
/**
 * @brief Create a SCSI-like(sdX) block device
 *
 * @return Pointer to blockdev or NULL with errno set
 */
unique_ptr<blockdev> blkdev_create_scsi_like_dev()
{
    unique_ptr<blockdev> dev = make_unique<blockdev>();

    if (!dev)
        return nullptr;

    auto number = next_scsi_dev_num++;

    // A SCSI node can have at max 3 characters (Zz)
    char numbuf[3];

    // If block_get_device_letter_from_id returns false, it means that it couldn't fit the
    // device number in the two alphabetic chars
    if (!block_get_device_letter_from_id(number, cul::slice<char>{numbuf, 3}))
        return errno = ENODEV, nullptr;

    dev->name = "sd";

    if (!dev->name || !dev->name.append(std::string_view{numbuf}))
        return errno = ENOMEM, nullptr;

    return cul::move(dev);
}

flush::writeback_dev *bdev_get_wbdev(struct inode *ino)
{
    flush::writeback_dev *dev;
    DCHECK(ino->i_sb != nullptr);

    if (ino->i_sb == bdev_sb)
        dev = ((struct block_inode *) ino)->b_wbdev;
    else
    {
        /* Find the block device, get the wbdev that way */
        blockdev *bdev = ino->i_sb->s_bdev;
        if (S_ISBLK(ino->i_mode))
            bdev = (blockdev *) ino->i_helper;
        DCHECK(bdev != nullptr);
        dev = bdev->wbdev.get();
    }

    DCHECK(dev != nullptr);
    return dev;
}

/* We provide two variants of the bio_req allocation. The first, common variant is bio_req + N
 * inline page vecs. This has prior literature in the Windows Kernel (IRPs) and the Linux kernel.
 * The second variant is the noinline bio_reqs, which simply allocate a struct bio_req, with nothing
 * else added onto it. This is useful when we have surpassed BIO_MAX_INLINE_VECS, and need a
 * separate heap allocation for it.
 */
static struct slab_cache *bio_cache_noinline;

#define BIO_MAX_ORDER 4
/* Provide 2^N inline vecs until we reach BIO_MAX_INLINE_VECS. For 8, we provide 1, 2, 4 and 8 */
static struct slab_cache *bio_cache_inline[BIO_MAX_ORDER];

__init static void bio_cache_init()
{
    bio_cache_noinline = kmem_cache_create("bio_req_noinline", sizeof(bio_req), 0, 0, nullptr);
    CHECK(bio_cache_noinline != nullptr);

    for (int i = 0; i < BIO_MAX_ORDER; i++)
    {
        char name[30];
        int inline_vecs = 1 << i;
        sprintf(name, "bio_req-%d", inline_vecs);

        char *slabname = strdup(name);
        CHECK(slabname != nullptr);

        bio_cache_inline[i] = kmem_cache_create(
            slabname, sizeof(struct bio_req) + inline_vecs * sizeof(struct page_iov), 0, 0,
            nullptr);
        CHECK(bio_cache_inline[i] != nullptr);
    }
}

static struct slab_cache *bio_pick_cache(size_t nr_vecs)
{
    DCHECK(nr_vecs != 0);
    if (nr_vecs < 2)
        return bio_cache_inline[0];
    size_t order = ilog2(nr_vecs - 1) + 1;
    DCHECK(order < BIO_MAX_ORDER);
    return bio_cache_inline[order];
}

/**
 * @brief Allocate a bio_req
 * The system will attempt to allocate a bio_req with an inline page_iov vector. If not possible, it
 * will allocate them on the heap.
 *
 * @param gfp_flags GFP flags
 * @param nr_vecs Number of vectors
 * @return The allocated, initialized bio_req
 */
struct bio_req *bio_alloc(unsigned int gfp_flags, size_t nr_vectors)
{
    struct bio_req *req;
    struct slab_cache *cache;
    bool no_inline_vecs = nr_vectors > BIO_MAX_INLINE_VECS;

    if (no_inline_vecs)
        cache = bio_cache_noinline;
    else
    {
        cache = bio_pick_cache(nr_vectors);
        DCHECK(cache->objsize >= sizeof(struct bio_req) + nr_vectors * sizeof(struct page_iov));
    }

    req = (struct bio_req *) kmem_cache_alloc(cache, gfp_flags);

    if (!req)
        return nullptr;
    bio_init(req);

    if (!no_inline_vecs)
        req->vec = req->b_inline_vec;
    else
    {
        req->vec = (struct page_iov *) kmalloc(sizeof(page_iov) * nr_vectors, gfp_flags);
        if (!req->vec)
        {
            kmem_cache_free(cache, req);
            return nullptr;
        }
    }

    req->nr_vecs = nr_vectors;
    return req;
}

/**
 * @brief Free a bio_req
 *
 * @param req Request to free
 */
void bio_free(struct bio_req *req)
{
    struct slab_cache *cache = bio_cache_noinline;
    if (req->nr_vecs <= BIO_MAX_INLINE_VECS)
        cache = bio_pick_cache(req->nr_vecs);
    else
        kfree(req->vec);
    kmem_cache_free(cache, req);
}

/* Design note: We store io-queues with pending completed requests in per-cpu data. Those then
 * are completed inside a softirq (SOFTIRQ_VECTOR_BLOCK). This lets the IRQ path be fast and
 * latency free, and lets us do many more things inside b_end_io. Also lets us allocate and
 * deallocate memory.
 */
struct block_pcpu_data
{
    /* We may not need a lock here... Think about it */
    struct spinlock lock;
    struct list_head pending_queues;
    struct list_head pending_bios;
    size_t completed_bios;
    size_t completed_sq;
};

static PER_CPU_VAR(struct block_pcpu_data block_pcpu);

static void block_pcpu_ctor(unsigned int cpu)
{
    struct block_pcpu_data *pcpu = get_per_cpu_ptr_any(block_pcpu, cpu);
    spinlock_init(&pcpu->lock);
    INIT_LIST_HEAD(&pcpu->pending_queues);
    INIT_LIST_HEAD(&pcpu->pending_bios);
}

INIT_LEVEL_CORE_PERCPU_CTOR(block_pcpu_ctor);

/**
 * @brief Queue a pending io_queue to get looked at after the bio_reqs
 * After completing bio requests, we want to see if we can start up the submission queues again.
 * So we queue io_queues, and look at them after completing outstanding bio_reqs.
 * @param queue Queue to complete
 */
void block_queue_pending_io_queue(io_queue *queue)
{
    struct block_pcpu_data *data = get_per_cpu_ptr(block_pcpu);
    unsigned long flags = spin_lock_irqsave(&data->lock);
    list_add_tail(&queue->pending_node_, &data->pending_queues);
    spin_unlock_irqrestore(&data->lock, flags);
    softirq_raise(SOFTIRQ_VECTOR_BLOCK);
}

/**
 * @brief Queue a to-be-completed bio to get completed
 *
 * @param bio bio to complete
 */
void bio_queue_pending_bio(struct bio_req *bio)
{
    struct block_pcpu_data *data = get_per_cpu_ptr(block_pcpu);
    unsigned long flags = spin_lock_irqsave(&data->lock);
    list_add_tail(&bio->list_node, &data->pending_bios);
    spin_unlock_irqrestore(&data->lock, flags);
    softirq_raise(SOFTIRQ_VECTOR_BLOCK);
}

/**
 * @brief Handle block IO completion (called from softirqs)
 *
 */
void block_handle_completion()
{
    DEFINE_LIST(pending_queues);
    DEFINE_LIST(pending_bios);
    struct block_pcpu_data *data = get_per_cpu_ptr(block_pcpu);
    unsigned long flags = spin_lock_irqsave(&data->lock);
    list_move(&pending_queues, &data->pending_queues);
    list_move(&pending_bios, &data->pending_bios);
    spin_unlock_irqrestore(&data->lock, flags);

    list_for_every_safe (&pending_bios)
    {
        struct bio_req *req = container_of(l, struct bio_req, list_node);
        list_remove(&req->list_node);
        req->b_queue->do_complete(req);
        data->completed_bios++;
    }

    list_for_every_safe (&pending_queues)
    {
        io_queue *queue = list_head_cpp<io_queue>::self_from_list_head(l);
        list_remove(&queue->pending_node_);
        queue->clear_pending();
        queue->restart_sq();
        data->completed_sq++;
    }
}
