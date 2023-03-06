/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_BLOCK_IO_QUEUE_H
#define _ONYX_BLOCK_IO_QUEUE_H

#include <onyx/list.h>
#include <onyx/spinlock.h>

struct bio_req;

/**
 * @brief Represents a hardware block IO queue
 *        Serves bio_req's in a non-blocking way.
 *
 */
class io_queue
{
protected:
    unsigned int nr_entries_;
    unsigned int used_entries_;
    spinlock lock_;
    struct list_head req_list_;

    /**
     * @brief Submits IO to a device
     *
     * @param req bio_req to submit
     * @return 0 on sucess, negative error codes
     */
    virtual int device_io_submit(bio_req *req) = 0;

public:
    constexpr io_queue(unsigned int nr_entries) : nr_entries_{nr_entries}, used_entries_{0}
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
     * @brief Submits a request
     *
     * @param req Request to add to the queue
     * @return 0 on success, negative error codes.
     */
    int submit_request(bio_req *req);
};

#endif
