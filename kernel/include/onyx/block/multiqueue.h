/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_BLOCK_MULTIQUEUE_H
#define _ONYX_BLOCK_MULTIQUEUE_H

struct blockdev;
struct bio_req;

int blk_mq_submit_request(struct blockdev *dev, struct bio_req *bio);

#endif
