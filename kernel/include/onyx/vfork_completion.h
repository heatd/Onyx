/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_VFORK_COMPLETION_H
#define _ONYX_VFORK_COMPLETION_H

#include <onyx/cpu.h>
#include <onyx/wait_queue.h>

#include <onyx/atomic.hpp>

struct vfork_completion
{
    wait_queue wq;
    atomic<bool> done;
    atomic<bool> may_exit;

public:
    vfork_completion()
    {
        init_wait_queue_head(&wq);
        done = false;
        may_exit = false;
    }

    int wait()
    {
        return wait_for_event(&wq, done);
    }

    void wake()
    {
        done = true;
        wait_queue_wake_all(&wq);
        may_exit = true;
    }

    void wait_to_exit()
    {
        while (!may_exit)
            cpu_relax();
    }
};

#endif
