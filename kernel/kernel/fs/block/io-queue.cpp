/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/block.h>
#include <onyx/block/io-queue.h>

/**
 * @brief Completes an IO request
 *
 * @param req Request
 */
void io_queue::complete_request(struct request *req)
{
    used_entries_--;
    bio_queue_pending_req(req);
    set_pending();
}

/**
 * @brief Submits a request
 *
 * @param req Request to add to the queue
 */
int io_queue::submit_request(struct request *req)
{
    scoped_lock<spinlock, true> g{lock_};
    req->r_queue = this;

    if (used_entries_ < nr_entries_ && list_is_empty(&req_list_))
    {
        used_entries_++;
        return device_io_submit(req);
    }

    list_add_tail(&req->r_queue_list_node, &req_list_);
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
        block_queue_pending_io_queue(this);
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
    __restart_queue();
}

/**
 * @brief Restart a queue.
 * The lock must be held.
 *
 */
void io_queue::__restart_queue()
{
    if (pull_sq() == 0)
        return;

    u32 free_entries = nr_entries_ - used_entries_;

    for (u32 i = 0; i < free_entries; i++)
    {
        if (list_is_empty(&req_list_))
            break;

        struct request *req =
            container_of(list_first_element(&req_list_), request, r_queue_list_node);
        list_remove(&req->r_queue_list_node);
        used_entries_++;
        int st = device_io_submit(req);
        if (st < 0)
        {
            DCHECK(st == -EAGAIN);
            /* TODO: Try again later? Is this even a good idea? */
            list_add(&req->r_queue_list_node, &req_list_);
            used_entries_--;
            return;
        }
    }
}

/**
 * @brief Submit a batch of requests
 *
 * @param req_list List of requests
 * @param nr_reqs Number of requests
 */
void io_queue::submit_batch(struct list_head *req_list, u32 nr_reqs)
{
    scoped_lock<spinlock, true> g{lock_};
    list_splice_tail(req_list, &req_list_);
    if (nr_entries_ - used_entries_ > 0)
        __restart_queue();
}
