/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_RCUWAIT_TYPES_H
#define _ONYX_RCUWAIT_TYPES_H

#include <onyx/rcupdate.h>
#include <onyx/thread.h>

struct rcuwait
{
    struct thread *task;
};

#endif
