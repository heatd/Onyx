/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "blk.hpp"

#include <onyx/id.h>
#include <onyx/log.h>

namespace virtio
{

static blk_features supported_features[] = {blk_features::size_max, blk_features::seg_max,
                                            blk_features::geometry, blk_features::ro,
                                            blk_features::blk_size, blk_features::topology,
                                            blk_features::discard,  blk_features::write_zeroes};

static uint32_t bio_req_to_virtio_blk_type(uint8_t op)
{
    switch (op)
    {
    // TODO: Add support for the others
    case BIO_REQ_READ_OP:
        return VIRTIO_BLK_T_IN;
    case BIO_REQ_WRITE_OP:
        return VIRTIO_BLK_T_OUT;
    default:
        return (uint32_t) -1;
    }
}

int blk_vdev::submit_request(struct bio_req *req)
{
    uint8_t op = req->flags & BIO_REQ_OP_MASK;

    // We allocate a meta page that will hold the header and status
    // Yes, it's a bit wasteful, but much faster than walking page tables for stack
    // variables' physical addresses
    struct page *meta_page = alloc_page(PAGE_ALLOC_NO_ZERO);
    if (!meta_page)
        return -ENOMEM;

    virtio_blk_request *breq = (virtio_blk_request *) PAGE_TO_VIRT(meta_page);
    virtio_blk_tail *btail = (virtio_blk_tail *) (breq + 1);

    breq->type = bio_req_to_virtio_blk_type(op);

    if (breq->type == (uint32_t) -1)
    {
        free_page(meta_page);
        return -EIO;
    }

    breq->sector = req->sector_number;
    breq->reserved = 0;
    btail->status = 0;

    const auto &requestq = get_vq(0);

    virtio_allocation_info alloc_info;
    virtio_completion completion;

    alloc_info.nr_vecs = req->nr_vecs + 2;
    alloc_info.vec = req->vec;
    alloc_info.context = meta_page;
    alloc_info.alloc_flags = VIRTIO_ALLOCATION_FLAG_WRITE;

    alloc_info.fill_function = [](size_t vec_nr,
                                  virtio_allocation_info &context) -> virtio_desc_info {
        page_iov v;
        auto meta_page = (page *) context.context;
        virtio_blk_request *req = (virtio_blk_request *) PAGE_TO_VIRT(meta_page);
        bool write = req->type == VIRTIO_BLK_T_IN;

        if (vec_nr == 0)
        {
            // First descriptor
            v.length = sizeof(virtio_blk_request);
            v.page_off = 0;
            v.page = meta_page;
            write = false;
        }
        else if (vec_nr == (context.nr_vecs - 1))
        {
            // Last descriptor
            v.length = sizeof(virtio_blk_tail);
            v.page = meta_page;
            v.page_off = sizeof(virtio_blk_request);
            write = true;
        }
        else
        {
            v = *(context.vec + vec_nr - 1);
        }

        uint32_t alloc_flags = write ? VIRTIO_ALLOCATION_FLAG_WRITE : 0;

        return {v, alloc_flags};
    };

    alloc_info.completion = &completion;

    requestq->allocate_descriptors(alloc_info, false);

    requestq->put_buffer(alloc_info, true);

    completion.wait();

    if (btail->status == VIRTIO_BLK_S_OK)
    {
        req->flags |= BIO_REQ_DONE;
    }
    else if (btail->status == VIRTIO_BLK_S_UNSUPP)
    {
        req->flags |= BIO_REQ_NOT_SUPP;
    }
    else if (btail->status == VIRTIO_BLK_S_IOERR)
    {
        req->flags |= BIO_REQ_EIO;
    }

    free_page(meta_page);

    return 0;
}

void blk_vdev::handle_used_buffer(const virtq_used_elem &elem, virtq *vq)
{
    auto completion = vq->get_completion(elem.id);

    assert(completion != nullptr);
    completion->wake();
}

namespace blk
{

int blk_submit_request(struct blockdev *dev, struct bio_req *req)
{
    auto blkdev = reinterpret_cast<virtio::blk_vdev *>(dev->device_info);

    req->sector_number += dev->offset / 512;
    return blkdev->submit_request(req);
}

} // namespace blk

bool blk_vdev::perform_subsystem_initialization()
{
    for (auto f : supported_features)
    {
        if (raw_has_feature(static_cast<unsigned long>(f)))
            signal_feature(static_cast<unsigned long>(f));
    }

    if (!do_device_independent_negotiation() || !finish_feature_negotiation())
    {
        set_failure();
        return false;
    }

    // Create the requestq queue
    if (!create_virtqueue(0, get_max_virtq_size(0)))
    {
        set_failure();
        return false;
    }

    finalise_driver_init();

    auto dev = blkdev_create_scsi_like_dev();

    if (!dev)
        return false;

    dev->submit_request = blk::blk_submit_request;
    dev->sector_size = 512;

    if (blkdev_init(dev.get()) < 0)
        return false;

    dev.release();
    return true;
}

blk_vdev::~blk_vdev()
{
}

unique_ptr<vdev> create_blk_device(pci::pci_device *dev)
{
    return make_unique<blk_vdev>(dev);
}

} // namespace virtio
