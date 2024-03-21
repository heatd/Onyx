/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_BLOCK_BLK_PLUG_H
#define _ONYX_BLOCK_BLK_PLUG_H

#include <onyx/bdev_base_types.h>
#include <onyx/block/request.h>
#include <onyx/thread.h>

__BEGIN_CDECLS

/**
 * @brief Start plugging.
 * If a plug is currently set, does nothing.
 *
 * @param plug Plug to set and initialize
 */
static inline void blk_start_plug(struct blk_plug *plug)
{
    struct thread *curr = get_current_thread();

    if (curr && !curr->plug)
    {
        INIT_LIST_HEAD(&plug->request_list);
        plug->nr_requests = 0;
        curr->plug = plug;
    }
}

static inline struct blk_plug *blk_get_current_plug(void)
{
    struct thread *curr = get_current_thread();
    if (curr)
        return curr->plug;
    return nullptr;
}

/**
 * @brief Flush pending requests
 *
 * @param plug Plug to flush
 */
void blk_flush_plug(struct blk_plug *plug);

/**
 * @brief End plugging
 * Unset the plug and flush it. If plug is not the current plug, does nothing.
 *
 * @param plug Plug to unset
 */
void blk_end_plug(struct blk_plug *plug);

/**
 * @brief Attempt to merge a bio with a plug
 *
 * @param plug Plug to merge with
 * @param bio Bio to merge
 * @return If successful, return true, else false
 */
bool blk_merge_plug(struct blk_plug *plug, struct bio_req *bio);

/**
 * @brief Add a request to a plug
 *
 * @param plug Plug to add to
 * @param req Request to add
 */
static void blk_add_plug(struct blk_plug *plug, struct request *req)
{
    list_add_tail(&req->r_queue_list_node, &plug->request_list);
    plug->nr_requests++;
}

__END_CDECLS

#ifdef __cplusplus

class blk_plug_guard
{
    struct blk_plug plug;

public:
    blk_plug_guard()
    {
        blk_start_plug(&plug);
    }

    ~blk_plug_guard()
    {
        blk_end_plug(&plug);
    }

    blk_plug_guard(blk_plug_guard &&) = delete;
    blk_plug_guard &operator=(blk_plug_guard &&) = delete;
    blk_plug_guard(const blk_plug_guard &) = delete;
    blk_plug_guard &operator=(const blk_plug_guard &) = delete;
};

#endif

#endif
