/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_PRIVATE_WAIT_IMPL_H
#define _ONYX_PRIVATE_WAIT_IMPL_H

#include <onyx/wait.h>
#include <onyx/wait_queue.h>

struct wait_token
{
    void *addr;
    bool (*complete_)(void *addr);
    unsigned int flags;
    wait_queue wq;
    struct list_head list_node;

    wait_token(void *addr, bool (*complete)(void *addr), unsigned int flags)
        : addr{addr}, complete_{complete}, flags{flags}
    {
        INIT_LIST_HEAD(&list_node);
        init_wait_queue_head(&wq);
    }

    bool complete() const;

    int wait();

    int wait(hrtime_t timeout);
};

#endif
