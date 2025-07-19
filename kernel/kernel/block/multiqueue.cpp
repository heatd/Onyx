/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/block.h>
#include <onyx/block/blk_plug.h>
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

    struct blk_plug *plug = blk_get_current_plug();
    if (plug)
    {
        /* Attempt to merge this bio to another request */
        if (blk_merge_plug(plug, bio))
        {
            plug_merges++;
            bio_get(bio);
            return 0;
        }
    }

    struct io_queue *ioq = dev->mq_ops->pick_queue(dev);
    DCHECK(ioq != nullptr);

    struct request *req = bio_req_to_request(bio);
    if (!req)
        return -ENOMEM;

    bio_get(bio);

    if (plug)
    {
        req->r_queue = ioq;
        /* If plugged (and we failed to merge!), add to the plug and leave */
        blk_add_plug(plug, req);
        return 0;
    }

    return ioq->submit_request(req);
}
