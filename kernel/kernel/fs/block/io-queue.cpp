/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/block.h>
#include <onyx/block/io-queue.h>

/**
 * @brief Completes an IO request. Requires the io queue lock to be held.
 *
 * @param req Request
 * @return New BIO req to complete, if one exists
 */
bio_req *io_queue::complete_request(bio_req *req)
{
    (void) req;
    if (list_is_empty(&req_list_))
    {
        used_entries_--;
        return nullptr;
    }

    auto l = list_first_element(&req_list_);

    auto elem = container_of(l, bio_req, list_node);
    list_remove(l);
    return elem;
}

/**
 * @brief Submits a request
 *
 * @param req Request to add to the queue
 */
int io_queue::submit_request(bio_req *req)
{
    scoped_lock<spinlock, true> g{lock_};

    if (used_entries_ < nr_entries_)
    {
        used_entries_++;
        return device_io_submit(req);
    }

    list_add_tail(&req->list_node, &req_list_);
    return 0;
}
