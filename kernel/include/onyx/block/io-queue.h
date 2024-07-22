/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_BLOCK_IO_QUEUE_H
#define _ONYX_BLOCK_IO_QUEUE_H

#include <onyx/bio.h>
#include <onyx/block/request.h>
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
    virtual int device_io_submit(bio_req *req)
    {
        return -EIO;
    }

    /**
     * @brief Submits IO to a device
     *
     * @param req struct request to submit
     * @return 0 on sucess, negative error codes
     */
    virtual int device_io_submit(struct request *req)
    {
        return -EIO;
    }

    /**
     * @brief Restart a queue.
     * The lock must be held.
     *
     */
    void __restart_queue();

public:
    list_head_cpp<io_queue> pending_node_{this};

    io_queue(unsigned int nr_entries) : nr_entries_{nr_entries}, pending_node_{this}
    {
        INIT_LIST_HEAD(&req_list_);
        spinlock_init(&lock_);
    }

    /**
     * @brief Completes an IO request
     *
     * @param req Request
     */
    void complete_request(struct request *req);

    /**
     * @brief Submits a request
     *
     * @param req Request to add to the queue
     */
    int submit_request(struct request *req);

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
     * @brief Complete a block request
     * Called from softirq context
     * @param req Request to complete
     */
    virtual void do_complete(struct request *req)
    {
        block_request_complete(req);
    }

    /**
     * @brief Restart the submission queue by "pulling"
     *
     * @return Error code
     */
    virtual int pull_sq()
    {
        return -ENOSYS;
    }

    /**
     * @brief "Pull" a submission queue entry from req_list_
     *
     * @return A valid struct request *, or nullptr
     */
    struct request *pull_sqe()
    {
        if (list_is_empty(&req_list_))
            return nullptr;

        struct request *req =
            container_of(list_first_element(&req_list_), struct request, r_queue_list_node);
        list_remove(&req->r_queue_list_node);
        used_entries_++;
        return req;
    }

    /**
     * @brief "Unpull" an sqe
     *
     * @param req Request to put back to the queue's head
     */
    void unpull_seq(struct request *req)
    {
        list_add(&req->r_queue_list_node, &req_list_);
        used_entries_--;
    }

    /**
     * @brief Submit a batch of requests
     *
     * @param req_list List of requests
     * @param nr_reqs Number of requests
     */
    void submit_batch(struct list_head *req_list, u32 nr_reqs);
};

#endif
