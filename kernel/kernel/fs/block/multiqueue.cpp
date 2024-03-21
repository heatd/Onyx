/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/block.h>
#include <onyx/block/io-queue.h>
#include <onyx/block/request.h>

int plug_merges = 0;

int blk_mq_submit_request(struct blockdev *dev, struct bio_req *bio)
{
    if (blkdev_is_partition(dev))
    {
        bio->sector_number += dev->offset / dev->sector_size;
        dev = dev->actual_blockdev;
        bio->bdev = dev;
    }

    DCHECK(dev->mq_ops && dev->mq_ops->pick_queue);

    struct io_queue *ioq = dev->mq_ops->pick_queue(dev);
    DCHECK(ioq != nullptr);

    struct request *req = bio_req_to_request(bio);
    if (!req)
        return -ENOMEM;

    bio_get(bio);
    return ioq->submit_request(req);
}
