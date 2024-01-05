/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_BIO_H
#define _ONYX_BIO_H

#include <onyx/bdev_base_types.h>
#include <onyx/compiler.h>

#define BIO_MAX_INLINE_VECS 8

/**
 * @brief Allocate a bio_req
 * The system will attempt to allocate a bio_req with an inline page_iov vector. If not possible, it
 * will allocate them on the heap.
 *
 * @param gfp_flags GFP flags
 * @param nr_vecs Number of vectors
 * @return The allocated, initialized bio_req
 */
struct bio_req *bio_alloc(unsigned int gfp_flags, size_t nr_vectors);

/**
 * @brief Free a bio_req
 *
 * @param req Request to free
 */
void bio_free(struct bio_req *req);

static inline void bio_init(struct bio_req *req)
{
    *req = {};
    req->b_ref = 1;
}

static inline void bio_get(struct bio_req *req)
{
    __atomic_add_fetch(&req->b_ref, 1, __ATOMIC_ACQUIRE);
}

static inline void bio_put(struct bio_req *req)
{
    if (__atomic_sub_fetch(&req->b_ref, 1, __ATOMIC_RELEASE) == 0)
        bio_free(req);
}

/**
 * @brief Submit a bio_req and wait for it to end
 *
 * @param dev Block device
 * @param req Request
 * @return errno-like result of the bio_req
 */
int bio_submit_req_wait(struct blockdev *dev, struct bio_req *req);

/**
 * @brief Complete a bio req
 * Callable from softirq context, and lower
 *
 * @param req Request to complete
 */
static inline void bio_do_complete(struct bio_req *req)
{
    req->flags |= BIO_REQ_DONE;
    if (req->b_end_io)
        req->b_end_io(req);
    bio_put(req);
}

#endif
