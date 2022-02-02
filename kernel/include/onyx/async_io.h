/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_ASYNC_IO_H
#define _ONYX_ASYNC_IO_H

#include <onyx/clock.h>
#include <onyx/wait_queue.h>

enum aio_status
{
    AIO_STATUS_OK = 0,
    AIO_STATUS_EIO = 1,
    AIO_STATUS_ETIMEOUT = 2
};

struct aio_req
{
    uint64_t req_start;
    uint64_t req_end;
    enum aio_status status;
    struct wait_queue wake_sem;
    void *cookie;
    bool signaled;
};

static inline void aio_req_init(struct aio_req *r)
{
    init_wait_queue_head(&r->wake_sem);
    r->req_start = r->req_end = 0;
    r->cookie = NULL;
    r->status = AIO_STATUS_OK;
    r->signaled = false;
}

static inline int aio_wait_on_req(struct aio_req *r, hrtime_t ___timeout)
{
    return wait_for_event_timeout(&r->wake_sem, r->signaled == true, ___timeout);
}

#endif
