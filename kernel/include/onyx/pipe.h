/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_PIPE_H
#define _ONYX_PIPE_H

#include <onyx/mutex.h>
#include <onyx/refcount.h>
#include <onyx/vfs.h>
#include <onyx/wait_queue.h>

#include <onyx/atomic.hpp>

int pipe_create(struct file **pipe_readable, struct file **pipe_writeable);

#endif
