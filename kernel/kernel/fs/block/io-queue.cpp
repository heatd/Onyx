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
    req->flags |= BIO_REQ_DONE;
    if (req->b_end_io)
        req->b_end_io(req);
    bio_put(req);

    scoped_lock<spinlock, true> g{lock_};
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
 * @brief Completes an IO request
 *
 * @param req Request
 */
void io_queue::complete_request2(bio_req *req)
{
    used_entries_--;
    bio_queue_pending_bio(req);
}

/**
 * @brief Submits a request
 *
 * @param req Request to add to the queue
 */
int io_queue::submit_request(bio_req *req)
{
    scoped_lock<spinlock, true> g{lock_};
    req->b_queue = this;

    if (used_entries_ < nr_entries_ && list_is_empty(&req_list_))
    {
        used_entries_++;
        return device_io_submit(req);
    }

    list_add_tail(&req->list_node, &req_list_);
    return 0;
}

/**
 * @brief Set an io_queue as holding pending completed requests.
 * This queues it in a percpu queue and raises a softirq, if needed.
 */
void io_queue::set_pending()
{
    /* Someone else is/has queued it, no work to be done here. */
    if (!(__atomic_fetch_or(&flags_, IO_QUEUE_PENDING_SOFTIRQ, __ATOMIC_RELEASE) &
          IO_QUEUE_PENDING_SOFTIRQ))
        return;
}

/**
 * @brief Clear an io_queue's pending flag. The io_queue must be unqueued
 * from the block_pcpu by then.
 *
 */
void io_queue::clear_pending()
{
    __atomic_and_fetch(&flags_, ~IO_QUEUE_PENDING_SOFTIRQ, __ATOMIC_RELEASE);
}

/**
 * @brief Try to restart the submission queue
 * Called from softirq context.
 *
 */
void io_queue::restart_sq()
{
    scoped_lock<spinlock, true> g{lock_};
    u32 free_entries = nr_entries_ - used_entries_;

    for (u32 i = 0; i < free_entries; i++)
    {
        struct bio_req *request = container_of(list_first_element(&req_list_), bio_req, list_node);
        list_remove(&request->list_node);
        int st = device_io_submit(request);
        if (st < 0)
        {
            DCHECK(st == -EAGAIN);
            /* TODO: Try again later? Is this even a good idea? */
            list_add(&request->list_node, &req_list_);
            return;
        }
    }
}
