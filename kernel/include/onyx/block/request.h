/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_BLOCK_REQUEST_H
#define _ONYX_BLOCK_REQUEST_H

#include <onyx/bdev_base_types.h>
#include <onyx/bio.h>

/**
 * @brief Allocate a request and fill it in with the bio
 *
 * @param bio BIO to use for the request
 * @return Allocated request, or NULL
 */
struct request *bio_req_to_request(struct bio_req *bio);

/**
 * @brief Free a request struct
 *
 * @param req Request to free
 */
void block_request_free(struct request *req);

#define list_head_to_request(l) (container_of(l, struct request, r_queue_list_node))

#ifdef __cplusplus
template <typename Callable>
void for_every_bio(struct request *req, Callable cb)
{
    list_for_every_safe (&req->r_bio_list)
    {
        struct bio_req *r = container_of(l, struct bio_req, list_node);
        cb(r);
    }
}

/**
 * @brief Complete a request
 * Callable from softirq context
 *
 * @param req Request to complete
 */
static inline void block_request_complete(struct request *req)
{
    for_every_bio(req, [req](struct bio_req *bio) {
        bio->flags |= (req->r_flags & BIO_STATUS_MASK);
        bio_do_complete(bio);
    });

    block_request_free(req);
}

#endif

#endif
