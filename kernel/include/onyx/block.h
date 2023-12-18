/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_BLOCK_H
#define _ONYX_BLOCK_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <onyx/culstring.h>
#include <onyx/dev.h>
#include <onyx/list.h>
#include <onyx/page.h>
#include <onyx/page_iov.h>
#include <onyx/types.h>

#include <onyx/slice.hpp>

/* Power management operations*/
#define BLKDEV_PM_SLEEP    1
#define BLKDEV_PM_SHUTDOWN 2
#define BLKDEV_PM_RESET    3

struct blockdev;

using sector_t = uint64_t;

#define BIO_REQ_OP_MASK         (0xff)
#define BIO_REQ_READ_OP         0
#define BIO_REQ_WRITE_OP        1
#define BIO_REQ_DEVICE_SPECIFIC 2

/* BIO flags start at bit 8 since bits 0 - 7 are reserved for operations */
/* Note that we still have 24 bits for flags, which should be More Than Enough(tm) */
#define BIO_REQ_DONE     (1 << 8)
#define BIO_REQ_EIO      (1 << 9)
#define BIO_REQ_TIMEOUT  (1 << 10)
#define BIO_REQ_NOT_SUPP (1 << 11)

struct bio_req
{
    uint32_t flags;
    sector_t sector_number;
    struct page_iov *vec;
    size_t nr_vecs;
    size_t curr_vec_index;
    blockdev *bdev;
    struct list_head list_node;
    unsigned long device_specific[4];
};

using __blkread = ssize_t (*)(size_t, size_t, void *, struct blockdev *);
using __blkwrite = ssize_t (*)(size_t, size_t, void *, struct blockdev *);
using __blkflush = int (*)(struct blockdev *);
using __blkpowermanagement = int (*)(int, struct blockdev *);

struct superblock;
struct inode;

struct blockdev
{
    __blkread read{};
    __blkwrite write{};
    __blkflush flush{};
    __blkpowermanagement power{};
    cul::string name;
    unsigned int sector_size{};
    /* Explicitly use uint64_t here to support LBA > 32, like the extremely popular LBA48 */
    uint64_t nr_sectors{};
    void *device_info{};
    struct list_head block_dev_head;
    struct blockdev *actual_blockdev{}; // isn't null when blockdev is a partition
    size_t offset{};
    int (*submit_request)(struct blockdev *dev, struct bio_req *req){};
    /* Inode backing this block dev. This mostly matters when doing internal I/O to this block dev,
     * without it being a device file that userspace opened.
     */
    struct inode *b_ino{};
    /* This will have the mounted superblock here if this block device is mounted */
    struct superblock *sb{};

    blkdev *dev{};

    // An optional partition prefix, like the 'p' in nvme0n1p1
    cul::string partition_prefix;

    constexpr blockdev() = default;
};

static inline bool blkdev_is_partition(struct blockdev *dev)
{
    return dev->actual_blockdev != nullptr;
}

static inline struct blockdev *blkdev_get_dev(struct file *f)
{
    return (struct blockdev *) f->f_ino->i_helper;
}

/*
 * Function: struct blockdev *blkdev_search(const char *name);
 * Description: Search for 'name' on the linked list
 * Return value: Returns a valid block device on success, NULL on error. Sets errno properly.
 * errno values: EINVAL - invalid argument;
 */
struct blockdev *blkdev_search(const char *name);
/*
 * Function: int blkdev_init(struct blockdev *dev);
 * Description: Adds dev to the registered block devices and initializes it.
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument
 */
int blkdev_init(struct blockdev *dev);
/*
 * Function: size_t blkdev_read(size_t offset, size_t count, void *buffer, struct blockdev *dev);
 * Description: Reads 'count' bytes from 'dev' to 'buffer', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
 */
ssize_t blkdev_read(size_t offset, size_t count, void *buffer, struct blockdev *dev);
/*
 * Function: size_t blkdev_write(size_t offset, size_t count, void *buffer, struct blockdev *dev);
 * Description: Writes 'count' bytes from 'buffer' to 'dev', with offset 'offset'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
 */
ssize_t blkdev_write(size_t offset, size_t count, void *buffer, struct blockdev *dev);
/*
 * Function: int blkdev_flush(struct blockdev *dev);
 * Description: Flushes storage device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
 */
int blkdev_flush(struct blockdev *dev);
/*
 * Function: int blkdev_power(int op, struct blockdev *dev);
 * Description: Performs power management operation 'op' on device 'dev'
 * Return value: 0 on success, -1 on error. Sets errno properly.
 * errno values: EINVAL - invalid argument; ENOSYS - operation not supported on storage device 'dev'
 */
int blkdev_power(int op, struct blockdev *dev);

int bio_submit_request(struct blockdev *dev, struct bio_req *req);

static inline bool block_get_device_letter_from_id(unsigned int id, cul::slice<char> buffer)
{
    if (id > 26)
    {
        buffer[0] = 'A' + id / 26;
        buffer[1] = 'a' + id % 26;

        if (buffer[1] > 'z')
            return false;
    }
    else
    {
        buffer[0] = 'a' + id;
        buffer[1] = '\0';
    }

    buffer[2] = '\0';

    return true;
}

/**
 * @brief Create a SCSI-like(sdX) block device
 *
 * @return Pointer to blockdev or NULL with errno set
 */
unique_ptr<blockdev> blkdev_create_scsi_like_dev();

// Read-write user and group, no permissions to others
#define BLOCK_DEVICE_PERMISSIONS 0660

struct blockdev;
void partition_setup_disk(struct blockdev *dev);

#endif
