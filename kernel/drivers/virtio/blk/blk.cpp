/*
 * Copyright (c) 2021 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "blk.hpp"

#include <onyx/block/multiqueue.h>
#include <onyx/id.h>
#include <onyx/log.h>

#include <linux/scatterlist.h>

namespace virtio
{

static blk_features supported_features[] = {
    blk_features::size_max, blk_features::seg_max,      blk_features::geometry,
    blk_features::ro,       blk_features::blk_size,     blk_features::topology,
    blk_features::discard,  blk_features::write_zeroes,
};

static uint32_t bio_req_to_virtio_blk_type(uint8_t op)
{
    switch (op)
    {
        // TODO: Add support for the others
        case BIO_REQ_READ_OP:
            return VIRTIO_BLK_T_IN;
        case BIO_REQ_WRITE_OP:
            return VIRTIO_BLK_T_OUT;
        case BIO_REQ_FLUSH_OP:
            return VIRTIO_BLK_T_FLUSH;
        default:
            return (uint32_t) -1;
    }
}

struct vdev_request_pdu
{
    struct virtio_blk_request request;
    struct virtio_blk_tail tail;
    struct sg_table table;
};

static inline struct vdev_request_pdu *request_to_pdu(struct request *req)
{
    return (struct vdev_request_pdu *) (req + 1);
}

void vdev_queue::do_complete(struct request *req)
{
    struct vdev_request_pdu *pdu = request_to_pdu(req);

    sg_free_table(&pdu->table);
    block_request_complete(req);
}

void blk_vdev::handle_used_buffer(const virtq_used_elem &elem, virtq *vq)
{
    struct request *req = (struct request *) vq->get_completion(elem.id);
    struct vdev_request_pdu *pdu = request_to_pdu(req);
    struct virtio_blk_tail *btail = &pdu->tail;

    assert(req != nullptr);
    if (btail->status == VIRTIO_BLK_S_OK)
        req->r_flags |= BIO_REQ_DONE;
    else if (btail->status == VIRTIO_BLK_S_UNSUPP)
        req->r_flags |= BIO_REQ_NOT_SUPP;
    else if (btail->status == VIRTIO_BLK_S_IOERR)
        req->r_flags |= BIO_REQ_EIO;

    req->r_queue->complete_request(req);
}

static void vdev_map_request(struct sg_table *table, struct request *req,
                             struct vdev_request_pdu *pdu)
{
    struct scatterlist *sg = table->sgl;

    sg_set_buf(sg, &pdu->request, sizeof(pdu->request));
    sg = sg_next(sg);
    for_every_bio(req, [&](struct bio_req *bio) {
        for_every_page_iov_in_bio(bio, [&](page_iov *iov) -> bool {
            sg_set_page(sg, iov->page, iov->length, iov->page_off);
            sg = sg_next(sg);
            return true;
        });
    });
    sg_set_buf(sg, &pdu->tail, sizeof(pdu->tail));
}

/**
 * @brief Submits IO to a device
 *
 * @param req struct request to submit
 * @return 0 on sucess, negative error codes
 */
int vdev_queue::device_io_submit(struct request *req)
{
    struct virtio_blk_request *breq;
    struct virtio_blk_tail *btail;
    struct vdev_request_pdu *pdu;
    unsigned int nr_sgls;
    int err;
    u8 op;

    pdu = request_to_pdu(req);
    nr_sgls = req->r_nr_sgls + 2;

    err = sg_alloc_table(&pdu->table, nr_sgls, GFP_ATOMIC);
    if (err)
        return err;

    vdev_map_request(&pdu->table, req, pdu);
    op = req->r_flags & BIO_REQ_OP_MASK;
    breq = &pdu->request;
    btail = &pdu->tail;

    err = -EIO;
    breq->type = bio_req_to_virtio_blk_type(op);
    if (breq->type == (uint32_t) -1)
        goto out_err;

    breq->sector = req->r_sector;
    breq->reserved = 0;
    btail->status = 0;

    err = vq->try_alloc_descs(nr_sgls, pdu->table.sgl,
                              1 + (breq->type == VIRTIO_BLK_T_OUT ? req->r_nr_sgls : 0));
    if (err)
        goto out_err;

    vq->set_completion(err, req);
    vq->put_buffer(err, true);
    return 0;
out_err:
    sg_free_table(&pdu->table);
    return err;
}

static struct io_queue *vdev_pick_queue(struct blockdev *bdev)
{
    return reinterpret_cast<virtio::blk_vdev *>(bdev->device_info)->request_queue.get();
}

const static struct blk_mq_ops vdev_mq_ops = {
    .pick_queue = vdev_pick_queue,
};

bool blk_vdev::perform_subsystem_initialization()
{
    struct queue_properties *qp;

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

    request_queue = make_unique<vdev_queue>(virtqueue_list[0].get(), this);
    if (!request_queue)
    {
        set_failure();
        return false;
    }

    finalise_driver_init();

    auto dev = blkdev_create_scsi_like_dev();

    if (!dev)
        return false;

    qp = &dev->bdev_queue_properties;
    dev->submit_request = blk_mq_submit_request;
    dev->sector_size = 512;
    dev->mq_ops = &vdev_mq_ops;
    dev->device_info = this;
    qp->max_sgl_desc_length = UINT32_MAX;
    qp->max_sgls_per_request = virtqueue_list[0]->get_queue_size() - 2;
    qp->request_extra_headroom = sizeof(struct vdev_request_pdu);
    dev->nr_sectors = read<u64>((unsigned long) blk_registers::capacity);

    if (has_feature((int) blk_features::size_max))
        qp->max_sgl_desc_length =
            min((u32) qp->max_sgl_desc_length, read<u32>((int) blk_registers::size_max));

    if (has_feature((int) blk_features::seg_max))
        qp->max_sgls_per_request =
            min((u32) qp->max_sgls_per_request, read<u32>((int) blk_registers::seg_max));

    pr_info("virtio_blk: device %s capacity %lu\n", dev->name.c_str(), dev->nr_sectors);
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
