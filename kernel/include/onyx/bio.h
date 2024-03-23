/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
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

__BEGIN_CDECLS

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
    *req = (struct bio_req){};
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

int bio_submit_request(struct blockdev *dev, struct bio_req *req);

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

/**
 * @brief Set the PINNED_PAGES flag in the bio req
 * This makes it so bio completion unpins the pages in page_iov.
 *
 * @param req Request
 */
static inline void bio_set_pinned(struct bio_req *req)
{
    req->flags |= BIO_REQ_PINNED_PAGES;
}

static inline void bio_request_init(struct request *req)
{
    *req = (struct request){};
    INIT_LIST_HEAD(&req->r_bio_list);
}

/**
 * @brief Push pages to a bio
 * This function adds {a section of some pages, a page, some pages, etc} to a bio's page vec.
 * The bio must have enough space for a new iov entry.
 *
 * @param bio BIO to operate on
 * @param page Page(s) to add
 * @param offset In-page offset
 * @param length Length of the data, in bytes
 */
static inline void bio_push_pages(struct bio_req *bio, struct page *page, unsigned int offset,
                                  unsigned int length)
{
    /* TODO: Once we work out any possible kinks, add page_iov merging */
    DCHECK(bio->curr_vec_index < bio->nr_vecs);
    size_t index = bio->curr_vec_index++;
    bio->vec[index].page = page;
    bio->vec[index].page_off = offset;
    bio->vec[index].length = length;
}

static void bio_reset_vec_index(struct bio_req *bio)
{
    bio->curr_vec_index = 0;
}

/**
 * @brief Clone a bio
 *
 * @param bio Bio to clone
 * @param gfp_flags GFP flags
 * @return Cloned BIO, or null
 */
struct bio_req *bio_clone(struct bio_req *bio, unsigned int gfp_flags);

static inline struct bio_req *bio_chained(struct bio_req *bio)
{
    /* Currently we're storing the chained bios in b_private */
    return (struct bio_req *) bio->b_private;
}

/**
 * @brief Bounce a BIO out of high mem
 *
 * @param original Original BIO to bounce
 * @param gfp_mask Mask (that limits our memory allocation)
 * @return New BIO (with bounced, valid buffers)
 */
struct bio_req *bio_bounce(struct bio_req *original, unsigned int gfp_mask);

enum bio_is_valid_result
{
    BIO_IS_VALID = 0,
    BIO_NEEDS_BOUNCE,
    BIO_IS_INVALID
};

/**
 * @brief Check if a given bio is valid (wrt the block device)
 *
 * @param bio Bio to check
 * @return bio_is_valid_result value
 */
enum bio_is_valid_result bio_is_valid(struct bio_req *bio);

/**
 * @brief Complete the chained, cloned bio
 *
 * @param bio BIO whose chain needs completion
 */
void bio_complete_cloned(struct bio_req *bio);

__END_CDECLS

#ifdef __cplusplus

template <typename Callable>
void for_every_page_iov_in_bio(struct bio_req *breq, Callable c)
{
    for (size_t i = 0; i < breq->nr_vecs; i++)
        if (!c(&breq->vec[i]))
            break;
}

#endif
#endif
