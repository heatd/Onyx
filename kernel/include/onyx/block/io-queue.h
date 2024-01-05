/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_BLOCK_IO_QUEUE_H
#define _ONYX_BLOCK_IO_QUEUE_H

#include <onyx/bio.h>
#include <onyx/list.h>
#include <onyx/spinlock.h>

struct bio_req;

#define IO_QUEUE_PENDING_SOFTIRQ (1 << 0)

/**
 * @brief Represents a hardware block IO queue
 *        Serves bio_req's in a non-blocking way.
 *
 */
struct io_queue
{
protected:
    unsigned int nr_entries_;
    unsigned int used_entries_{0};
    spinlock lock_;
    unsigned int flags_{0};
    struct list_head req_list_;

    /**
     * @brief Submits IO to a device
     *
     * @param req bio_req to submit
     * @return 0 on sucess, negative error codes
     */
    virtual int device_io_submit(bio_req *req) = 0;

public:
    list_head_cpp<io_queue> pending_node_{this};

    constexpr io_queue(unsigned int nr_entries) : nr_entries_{nr_entries}
    {
        INIT_LIST_HEAD(&req_list_);
        spinlock_init(&lock_);
    }

    /**
     * @brief Completes an IO request
     *
     * @param req Request
     * @return New BIO req to complete, if one exists
     */
    bio_req *complete_request(bio_req *req);

    /**
     * @brief Completes an IO request
     *
     * @param req Request
     */
    void complete_request2(bio_req *req);

    /**
     * @brief Submits a request
     *
     * @param req Request to add to the queue
     * @return 0 on success, negative error codes.
     */
    int submit_request(bio_req *req);

    /**
     * @brief Set an io_queue as holding pending completed requests.
     * This queues it in a percpu queue and raises a softirq, if needed.
     */
    void set_pending();

    /**
     * @brief Clear an io_queue's pending flag. The io_queue must be unqueued
     * from the block_pcpu by then.
     *
     */
    void clear_pending();

    /**
     * @brief Try to restart the submission queue
     * Called from softirq context.
     *
     */
    void restart_sq();

    /**
     * @brief Complete a bio_req
     * Called from softirq context
     * @param req Request to complete
     */
    virtual void do_complete(bio_req *req)
    {
        bio_do_complete(req);
    }
};

#endif
