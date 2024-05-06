/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
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
#include <sys/mount.h>

#include <onyx/block.h>
#include <onyx/block/blk_plug.h>
#include <onyx/block/io-queue.h>
#include <onyx/buffer.h>
#include <onyx/filemap.h>
#include <onyx/init.h>
#include <onyx/local_lock.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/page_iov.h>
#include <onyx/process.h>
#include <onyx/rwlock.h>
#include <onyx/softirq.h>

#include <uapi/fcntl.h>

static int block_reread_parts(struct blockdev *bdev);

unsigned int blkdev_ioctl(int request, void *argp, struct file *f)
{
    auto d = (blockdev *) f->f_ino->i_helper;

    switch (request)
    {
        case BLKGETSIZE64: {
            u64 len = d->nr_sectors * d->sector_size;
            return copy_to_user(argp, &len, sizeof(u64));
        }

        case BLKRRPART: {
            return block_reread_parts(d);
        }

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
    blk->block_size = blk->sector_size;
    auto ex = dev_register_blockdevs(0, 1, 0, &buffer_ops, cul::string{blk->name});
    if (ex.has_error())
        return ex.error();

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

    mutex_lock(&blk->bdev_lock);
    if (!blkdev_is_partition(blk))
        partition_setup_disk(blk);
    mutex_unlock(&blk->bdev_lock);

    if (blk->actual_blockdev)
    {
        /* We have a parent blockdev, add ourselves to it. */
        struct blockdev *parent = blk->actual_blockdev;
        MUST_HOLD_MUTEX(&parent->bdev_lock);
        DCHECK(parent->actual_blockdev == nullptr);
        list_add_tail(&blk->partition_head, &parent->partition_list);
    }

    return 0;
}

int bio_submit_request(struct blockdev *dev, struct bio_req *req)
{
    if (unlikely(dev->submit_request == nullptr))
        return -EIO;

    req->bdev = dev;
    bio_reset_vec_index(req);

    bio_is_valid_result result = bio_is_valid(req);
    if (unlikely(result == BIO_IS_INVALID))
        return -EIO;
    else if (unlikely(result == BIO_NEEDS_BOUNCE))
    {
        req = bio_bounce(req, GFP_NOIO);
        if (!req)
            return NULL;
    }

    return dev->submit_request(dev, req);
}

static void bio_submit_sync_end_io(struct bio_req *req)
{
    u32 *flags = (u32 *) req->b_private;
    *flags = req->flags;
    wake_address(flags);
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
    u32 flags = 0;
    req->b_end_io = bio_submit_sync_end_io;
    req->b_private = &flags;

    int st = bio_submit_request(dev, req);
    if (st < 0)
        return st;

    wait_for(
        &flags,
        [](void *pflags) -> bool {
            u32 fl = *(u32 *) pflags;
            return fl & BIO_REQ_DONE;
        },
        WAIT_FOR_FOREVER, 0);

    if (flags & (BIO_REQ_EIO | BIO_REQ_NOT_SUPP))
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
        req->vec = (struct page_iov *) kcalloc(nr_vectors, sizeof(page_iov), gfp_flags);
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
 * @brief Unpin user pages and perform dirtying-related tasks (when destroying a bio)
 *
 * @param req Request whose pages to unpin
 */
static void bio_unpin_pages(struct bio_req *req)
{
    /* Ok, a bio_req is being destroyed. Unpin the pages (page_unref).
     * TODO: In the future, worry about dirtying (when the given pages are in the page cache). */
    for (size_t i = 0; i < req->nr_vecs; i++)
    {
        struct page *page = req->vec[i].page;
        /* Sidenote: It's possible some pages are NULL, if we failed mid-bio-construction and are
         * bio_put'ing that. So check for that. */
        if (page)
            page_unref(page);
    }
}

/**
 * @brief Free a bio_req
 *
 * @param req Request to free
 */
void bio_free(struct bio_req *req)
{
    struct slab_cache *cache = bio_cache_noinline;
    if (req->flags & BIO_REQ_CLONED) [[unlikely]]
        bio_put((struct bio_req *) req->b_private);

    if (req->flags & BIO_REQ_PINNED_PAGES) [[unlikely]]
        bio_unpin_pages(req);

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
    struct local_lock lock;
    struct list_head pending_queues GUARDED_BY(lock);
    struct list_head pending_reqs GUARDED_BY(lock);
    /* Note: completed_reqs and completed_sq do not need a lock, they're already guarded by
     * being in softirq context. */
    size_t completed_reqs;
    size_t completed_sq;
};

static PER_CPU_VAR(struct block_pcpu_data block_pcpu);

static void block_pcpu_ctor(unsigned int cpu)
{
    struct block_pcpu_data *pcpu = get_per_cpu_ptr_any(block_pcpu, cpu);
    local_lock_init(&pcpu->lock);
    INIT_LIST_HEAD(&pcpu->pending_queues);
    INIT_LIST_HEAD(&pcpu->pending_reqs);
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
    unsigned long flags = local_lock_irqsave(&data->lock);
    list_add_tail(&queue->pending_node_, &data->pending_queues);
    local_unlock_irqrestore(&data->lock, flags);
    softirq_raise(SOFTIRQ_VECTOR_BLOCK);
}

/**
 * @brief Queue a to-be-completed bio to get completed
 *
 * @param bio bio to complete
 */
void bio_queue_pending_req(struct request *req)
{
    struct block_pcpu_data *data = get_per_cpu_ptr(block_pcpu);
    unsigned long flags = local_lock_irqsave(&data->lock);
    list_add_tail(&req->r_queue_list_node, &data->pending_reqs);
    local_unlock_irqrestore(&data->lock, flags);
    softirq_raise(SOFTIRQ_VECTOR_BLOCK);
}

/**
 * @brief Handle block IO completion (called from softirqs)
 *
 */
void block_handle_completion()
{
    DEFINE_LIST(pending_queues);
    DEFINE_LIST(pending_reqs);
    struct block_pcpu_data *data = get_per_cpu_ptr(block_pcpu);
    unsigned long flags = local_lock_irqsave(&data->lock);
    list_move(&pending_queues, &data->pending_queues);
    list_move(&pending_reqs, &data->pending_reqs);
    local_unlock_irqrestore(&data->lock, flags);

    list_for_every_safe (&pending_reqs)
    {
        struct request *req = container_of(l, struct request, r_queue_list_node);
        list_remove(&req->r_queue_list_node);
        req->r_queue->do_complete(req);
        data->completed_reqs++;
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

/**
 * @brief Flush pending requests
 *
 * @param plug Plug to flush
 */
void blk_flush_plug(struct blk_plug *plug)
{
    /* We flush the plug by keeping a list of the most recent run of requests that belong to the
     * same queue. When we find a request with another queue, or reach the end of the list, we
     * submit the requests in a batched fashion. */
    DEFINE_LIST(reqs);
    u32 nr_reqs = 0;
    struct io_queue *last_queue = nullptr;

    list_for_every_safe (&plug->request_list)
    {
        struct request *req = container_of(l, struct request, r_queue_list_node);
        list_remove(&req->r_queue_list_node);
        plug->nr_requests--;

        struct io_queue *queue = req->r_queue;

        if (queue != last_queue)
        {
            if (last_queue)
                last_queue->submit_batch(&reqs, nr_reqs);
            last_queue = queue;
        }

        list_add_tail(&req->r_queue_list_node, &reqs);
        nr_reqs++;
    }

    if (!list_is_empty(&reqs))
        last_queue->submit_batch(&reqs, nr_reqs);
}

/**
 * @brief End plugging
 * Unset the plug and flush it. If plug is not the current plug, does nothing.
 *
 * @param plug Plug to unset
 */
void blk_end_plug(struct blk_plug *plug)
{
    thread *curr = get_current_thread();
    if (curr->plug == plug)
    {
        /* This is *our* plug, unset and flush it. */
        blk_flush_plug(plug);
        curr->plug = nullptr;
    }
}

/**
 * @brief Set the block device's block size
 *
 * @param bdev Block device
 * @param block_size Block size
 * @return 0 on success, negative error codes
 */
int block_set_bsize(struct blockdev *bdev, unsigned int block_size)
{
    int st;

    if (count_bits(block_size) > 1)
    {
        pr_err("%s: desired block size %u is not a power of 2\n", bdev->name.c_str(), block_size);
        return -EINVAL;
    }

    if (block_size < bdev->sector_size)
    {
        pr_err("%s: desired block size %u is smaller than sector size %u\n", bdev->name.c_str(),
               block_size, bdev->sector_size);
        return -EINVAL;
    }

    if (block_size > PAGE_SIZE)
    {
        /* Note: This is not strictly an error, we just don't support it for now */
        pr_err("%s: desired block size %u is larger than page size %lu\n", bdev->name.c_str(),
               block_size, PAGE_SIZE);
        return -EINVAL;
    }

    /* Synchronize the block device's page cache and truncate all the pages out! This fixes issues
     * with stale block_buffer data. */
    if (st = filemap_fdatasync(bdev->b_ino, 0, -1UL); st < 0)
    {
        pr_err("%s: fdatasync failed: %d\n", bdev->name.c_str(), st);
        return st;
    }

    bdev->block_size = block_size;

    if (st = vmo_punch_range(bdev->b_ino->i_pages, 0, -1UL); st < 0)
    {
        pr_err("%s: vmo_punch_range failed: %d\n", bdev->name.c_str(), st);
        return st;
    }

    return 0;
}

int bdev_do_open(struct blockdev *bdev, bool exclusive) NO_THREAD_SAFETY_ANALYSIS
{
    int st = -EBUSY;
    /* Okay, we need to be a bit careful about the locking. But basically, blockdevs can't vanish
     * without their children going away. And partitions can't be opened without touching the parent
     * disk either. */
    struct blockdev *disk = bdev->actual_blockdev;
    if (disk)
        mutex_lock(&disk->bdev_lock);
    mutex_lock(&bdev->bdev_lock);

    if (exclusive && bdev->nr_busy > 0)
        goto out;

    bdev->nr_busy++;
    if (disk)
        disk->nr_open_partitions++;
    st = 0;
out:
    mutex_unlock(&bdev->bdev_lock);
    if (disk)
        mutex_unlock(&disk->bdev_lock);
    return st;
}

void bdev_release(struct blockdev *bdev) NO_THREAD_SAFETY_ANALYSIS
{
    struct blockdev *disk = bdev->actual_blockdev;
    if (disk)
        mutex_lock(&disk->bdev_lock);
    mutex_lock(&bdev->bdev_lock);

    bdev->nr_busy--;
    if (disk)
        disk->nr_open_partitions--;

    mutex_unlock(&bdev->bdev_lock);
    if (disk)
        mutex_unlock(&disk->bdev_lock);
}

#define BDEV_PRIVATE_UNDO (void *) 1

int bdev_on_open(struct file *f)
{
    DCHECK(S_ISBLK(f->f_ino->i_mode));
    struct blockdev *dev = (blockdev *) f->f_ino->i_helper;
    int st = bdev_do_open(dev, f->f_flags & O_EXCL);
    if (st == 0)
        f->private_data = BDEV_PRIVATE_UNDO;
    return st;
}

void bdev_release(struct file *f)
{
    DCHECK(S_ISBLK(f->f_ino->i_mode));
    struct blockdev *dev = (blockdev *) f->f_ino->i_helper;
    if (f->private_data == BDEV_PRIVATE_UNDO)
        bdev_release(dev);
}

static void bdev_teardown(struct blockdev *bdev)
{
    /* TODO: Currently, we're leaking blockdevs. This is /okay/ for the time being, but it really
     * shouldn't be the case. We need to handle device teardown. */
    list_remove(&bdev->partition_head);
    CHECK(dev_unregister_dev(bdev->dev, true) == 0);
}

static int block_reread_parts(struct blockdev *bdev)
{
    int st = -EBUSY;

    if (!is_root_user())
        return -EPERM;

    if (st = filemap_fdatasync(bdev->b_ino, 0, -1UL); st < 0)
    {
        pr_err("%s: sync failed: %d\n", bdev->name.c_str(), st);
        return st;
    }

    mutex_lock(&bdev->bdev_lock);

    if (bdev->nr_open_partitions > 0)
        goto out;

    /* Tear down the partitions and create new ones */
    list_for_every_safe (&bdev->partition_list)
    {
        struct blockdev *child = container_of(l, struct blockdev, partition_head);
        bdev_teardown(child);
    }

    partition_setup_disk(bdev);
    st = 0;

out:
    mutex_unlock(&bdev->bdev_lock);
    return st;
}
