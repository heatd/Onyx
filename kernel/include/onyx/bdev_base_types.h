/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_BDEV_BASE_TYPES_H
#define _ONYX_BDEV_BASE_TYPES_H

#include <onyx/list.h>
#include <onyx/page_iov.h>
#include <onyx/types.h>

/* Keep basic bdev types that are universally used and exported to consumers here. Do not keep
 * blockdev nor io_queue here.
 */

struct blockdev;
struct io_queue;

typedef u64 sector_t;

#define BIO_REQ_OP_MASK         (0xff)
#define BIO_REQ_READ_OP         0
#define BIO_REQ_WRITE_OP        1
#define BIO_REQ_DEVICE_SPECIFIC 2

/* BIO flags start at bit 8 since bits 0 - 7 are reserved for operations */
/* Note that we still have 24 bits for flags, which should be More Than Enough(tm) */
#define BIO_REQ_DONE         (1 << 8)
#define BIO_REQ_EIO          (1 << 9)
#define BIO_REQ_TIMEOUT      (1 << 10)
#define BIO_REQ_NOT_SUPP     (1 << 11)
#define BIO_REQ_PINNED_PAGES (1 << 12)

#define BIO_STATUS_MASK (BIO_REQ_DONE | BIO_REQ_EIO | BIO_REQ_TIMEOUT | BIO_REQ_NOT_SUPP)

struct bio_req
{
    unsigned int b_ref;
    uint32_t flags;
    sector_t sector_number;
    struct page_iov *vec;
    size_t nr_vecs;
    size_t curr_vec_index;
    struct blockdev *bdev;
    struct io_queue *b_queue;
    struct list_head list_node;
    /* TODO: We need to kill this! */
    unsigned long device_specific[4];
    void (*b_end_io)(struct bio_req *req);
    void *b_private;
    struct page_iov b_inline_vec[];
};

/**
 * @brief Represents a hardware IO request
 * The stack more or less works like this: the bio_req is the unit of IO submission *for the
 * submitter*. At some point in the bio submission path, the stack either creates a struct request
 * for it or merges the bio with another request. The struct request is the unit of IO submission
 * *for the driver/hardware*. At this point, bios have been split and/or have been merged together.
 * The idea is that they more or less correspond to the actual hw submission, and as such one can
 * easily convert directly to the controller's format; the drivers provide queue limits such that
 * generic code can correctly concatenate and split requests.
 *
 * The lifetime for requests is roughly:
 * bio is allocated -> bio_submit_request -> allocate request -> lock queue and append.
 * As such, we don't need a ref count or a lock. The lifetime is relatively strict:
 * NEW -> QUEUED -> SUBMITTED -> COMPLETED.
 */
struct request
{
    /* Mirrors BIO_REQ flags */
    u32 r_flags;
    sector_t r_sector;
    sector_t r_nsectors;
    struct blockdev *r_bdev;
    struct io_queue *r_queue;
    /* The request's bio list. Requests 'own' bios and keep a reference to them, which is put when
     * the request is completed. */
    struct list_head r_bio_list;
    struct list_head r_queue_list_node;
    size_t r_nr_sgls;
    /* Anything can come after this. Block devices specify their request's sizes, and data is
     * allocated inline. */
};

static inline void *b_request_to_data(struct request *req)
{
    return req + 1;
}

#endif
