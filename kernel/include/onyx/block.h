/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
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

#include <onyx/bdev_base_types.h>
#include <onyx/bio.h>
#include <onyx/culstring.h>
#include <onyx/dev.h>
#include <onyx/list.h>
#include <onyx/mm/flush.h>
#include <onyx/page.h>
#include <onyx/types.h>

#include <onyx/slice.hpp>

/* Power management operations*/
#define BLKDEV_PM_SLEEP    1
#define BLKDEV_PM_SHUTDOWN 2
#define BLKDEV_PM_RESET    3

using __blkflush = int (*)(struct blockdev *);
using __blkpowermanagement = int (*)(int, struct blockdev *);

struct superblock;
struct inode;

struct blockdev
{
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

    unique_ptr<flush::writeback_dev> wbdev{nullptr};

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

void partition_setup_disk(struct blockdev *dev);

flush::writeback_dev *bdev_get_wbdev(struct inode *ino);

/**
 * @brief Handle block IO completion (called from softirqs)
 *
 */
void block_handle_completion();

/**
 * @brief Queue a pending io_queue to get looked at after the bio_reqs
 * After completing bio requests, we want to see if we can start up the submission queues again. So
 * we queue io_queues, and look at them after completing outstanding bio_reqs.
 * @param queue Queue to complete
 */
void block_queue_pending_io_queue(io_queue *queue);

/**
 * @brief Queue a to-be-completed bio to get completed
 *
 * @param bio bio to complete
 */
void bio_queue_pending_bio(struct bio_req *bio);

#endif
