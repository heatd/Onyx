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

size_t blkdev_read_file(size_t offset, size_t len, void *buffer, struct file *f)
{
    if (f->f_flags & O_NONBLOCK)
        return -EWOULDBLOCK;

    auto d = (blockdev *) f->f_ino->i_helper;
    /* align the offset first */
    size_t misalignment = offset % d->sector_size;
    ssize_t sector = offset / d->sector_size;
    size_t read = 0;
    char *buf = (char *) buffer;

    if (misalignment != 0)
    {
        // printk("handling misalignment\n");
        /* *sigh* yuck, we'll need to allocate a bounce buffer */
        struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
        if (!p)
        {
            return -ENOMEM;
        }

        void *virt = PAGE_TO_VIRT(p);

        // printk("reading sector %lu, %u bytes\n", sector, d->sector_size);

        ssize_t s = blkdev_read(sector * d->sector_size, d->sector_size, virt, d);

        size_t to_copy = min((d->sector_size - misalignment), len);

        if (s < 0)
        {
            free_page(p);
            return -errno;
        }

        memcpy(buf, (char *) virt + misalignment, to_copy);

        free_page(p);

        sector++;
        read = to_copy;
        buf += read;
        len -= read;
        // printk("len: %lu\n", len);
    }

    // printk("len: %lu\n", len);

    if (len != 0 && len / d->sector_size)
    {
        size_t nr_sectors = len / d->sector_size;
        size_t reading = nr_sectors * d->sector_size;

        // printk("Read: %lu\n", read);
        // printk("here, buf %p\n", buf);
        ssize_t s = blkdev_read(sector * d->sector_size, reading, buf, d);
        if (s < 0)
        {
            return -ENXIO;
        }

        len -= reading;
        buf += reading;
        read += reading;
        sector += nr_sectors;
    }

    if (len != 0)
    {
        struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
        if (!p)
        {
            return -ENOMEM;
        }

        void *virt = PAGE_TO_VIRT(p);

        ssize_t s = blkdev_read(sector * d->sector_size, d->sector_size, virt, d);

        if (s < 0)
        {
            free_page(p);
            return -errno;
        }

        memcpy(buf, (char *) virt, len);

        free_page(p);

        sector++;
        read += len;
        buf += len;
        len -= len;
    }

    return read;
}

size_t blkdev_write_file(size_t offset, size_t len, void *buffer, struct file *f)
{
    auto d = (blockdev *) f->f_ino->i_helper; /* align the offset first */
    size_t misalignment = offset % d->sector_size;
    ssize_t sector = offset / d->sector_size;
    size_t written = 0;
    char *buf = (char *) buffer;

    if (misalignment != 0)
    {
        /* *sigh* yuck, we'll need to allocate a bounce buffer */
        struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
        if (!p)
        {
            return errno = ENOMEM, -1;
        }

        void *virt = PAGE_TO_VIRT(p);

        ssize_t s = blkdev_read(sector * d->sector_size, d->sector_size, virt, d);

        size_t to_copy = min((d->sector_size - misalignment), len);

        if (s < 0)
        {
            free_page(p);
            return -1;
        }

        memcpy((char *) virt + misalignment, buf, to_copy);

        s = blkdev_write(sector * d->sector_size, d->sector_size, virt, d);
        free_page(p);

        if (s < 0)
        {
            return -1;
        }

        sector++;
        written += to_copy;
        buf += to_copy;
        len -= to_copy;
    }

    if (len != 0)
    {
        size_t nr_sectors = len / d->sector_size;
        size_t writing = nr_sectors * d->sector_size;

        ssize_t s = blkdev_write(sector * d->sector_size, writing, buf, d);
        if (s < 0)
        {
            return errno = ENXIO, -1;
        }

        len -= writing;
        buf += writing;
        written += writing;
        sector += nr_sectors;
    }

    if (len != 0)
    {
        struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
        if (!p)
        {
            return errno = ENOMEM, -1;
        }

        void *virt = PAGE_TO_VIRT(p);

        ssize_t s = blkdev_read(sector * d->sector_size, d->sector_size, virt, d);

        if (s < 0)
        {
            free_page(p);
            return -1;
        }

        memcpy(buf, (char *) virt, len);

        s = blkdev_write(sector * d->sector_size, d->sector_size, virt, d);
        free_page(p);

        if (s < 0)
        {
            return -1;
        }

        sector++;
        written += len;
        buf += len;
        len -= len;
    }

    return written;
}

const struct vm_object_ops blk_vmo_ops = {.commit = bbuffer_commit};

const struct file_ops blkdev_ops = {
    .read = blkdev_read_file,
    .write = blkdev_write_file,
    .ioctl = blkdev_ioctl,
};

struct superblock *bdev_sb;

/**
 * @brief blockdevfs inode
 *
 */
struct block_inode
{
    struct inode b_inode;

    /**
     * @brief Create a new blockdev inode
     *
     * @arg dev Block device
     * @return Properly set up blockdev inode, or NULL
     */
    static unique_ptr<block_inode> create(const struct blockdev *dev);
};

/**
 * @brief Create a new blockdev inode
 *
 * @arg dev Block device
 * @return Properly set up blockdev inode, or NULL
 */
unique_ptr<block_inode> block_inode::create(const struct blockdev *dev)
{
    unique_ptr<block_inode> ino = make_unique<block_inode>();
    if (!ino)
        return nullptr;
    auto &inode = ino->b_inode;

    if (inode_init(&inode, true) < 0)
        return nullptr;
    inode.i_dev = dev->dev->dev();
    inode.i_sb = bdev_sb;

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

int blkdev_init(struct blockdev *blk)
{
    /* XXX replace with the blockdev inode */
    blk->vmo = vmo_create(blk->nr_sectors * blk->sector_size, blk);
    if (!blk->vmo)
        return -ENOMEM;
    blk->vmo->ops = &blk_vmo_ops;
    blk->vmo->priv = blk;

    rw_lock_write(&dev_list_lock);

    list_add_tail(&blk->block_dev_head, &dev_list);

    rw_unlock_write(&dev_list_lock);

    auto ex = dev_register_blockdevs(0, 1, 0, &blkdev_ops, cul::string{blk->name});

    if (ex.has_error())
    {
        return ex.error();
    }

    auto dev = ex.value();

    dev->private_ = blk;
    dev->show(BLOCK_DEVICE_PERMISSIONS);

    blk->dev = dev;

    auto ino = block_inode::create(blk);
    if (!ino)
    {
        dev_unregister_dev(dev, true);
        return -ENOMEM;
    }

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
