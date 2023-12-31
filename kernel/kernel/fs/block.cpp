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
#include <onyx/buffer.h>
#include <onyx/filemap.h>
#include <onyx/page.h>
#include <onyx/page_iov.h>
#include <onyx/rwlock.h>

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
 * Function: size_t blkdev_read(size_t offset, size_t count, void *buffer, struct blockdev *dev);
 * Description: Reads 'count' bytes from 'dev' to 'buffer', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
 */
ssize_t blkdev_read(size_t offset, size_t count, void *buffer, struct blockdev *dev)
{
    if (count == 0)
        return 0;

    if (blkdev_is_partition(dev))
        return blkdev_read(dev->offset + offset, count, buffer, dev->actual_blockdev);

    struct page_iov v;
    unsigned long phys = (unsigned long) virtual2phys(buffer);

    v.page = phys_to_page(phys);
    v.length = (unsigned int) count;
    v.page_off = phys & (PAGE_SIZE - 1);

    struct bio_req r;
    r.nr_vecs = 1;
    r.vec = &v;
    r.nr_vecs = 1;
    r.sector_number = offset / dev->sector_size;
    r.flags = BIO_REQ_READ_OP;
    r.curr_vec_index = 0;

    return bio_submit_request(dev, &r);
}
/*
 * Function: size_t blkdev_write(size_t offset, size_t count, void *buffer, struct blockdev *dev);
 * Description: Writes 'count' bytes from 'buffer' to 'dev', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; EIO - operation not supported on storage device 'dev'
 */
ssize_t blkdev_write(size_t offset, size_t count, void *buffer, struct blockdev *dev)
{
    if (count == 0)
        return 0;

    if (blkdev_is_partition(dev))
        return blkdev_write(dev->offset + offset, count, buffer, dev->actual_blockdev);
    if (!dev->write)
        return errno = EIO, -1;

    return dev->write(offset, count, buffer, dev);
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
