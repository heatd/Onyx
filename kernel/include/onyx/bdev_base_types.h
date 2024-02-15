/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
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
    unsigned long device_specific[4];
    void (*b_end_io)(struct bio_req *req);
    void *b_private;
    struct page_iov b_inline_vec[];
};

#endif
