/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_KTRACE_H
#define _UAPI_KTRACE_H

#include <onyx/limits.h>
#include <onyx/types.h>

#include <uapi/ioctl.h>

struct ktrace_enable
{
    __u32 status;
    __u32 flags;
    __u32 buffer_size;
    __u32 evid;
};

/**
 * @brief Given an event id, get the format of its trace data. format_size is an IN/OUT
 * argument, taking a buffer size on input; on output, the actual size of the format is stored.
 *
 */
struct ktrace_event_format
{
    __u32 evid;
    __u32 format_size;
    char format[];
};

/**
 * @brief Get the event id behind a particular format name
 *
 */
struct ktrace_getevid_format
{
    char name[NAME_MAX + 1];
    __u32 evid;
};

#define KTRACE_ENABLE_STATUS_ENABLED  1
#define KTRACE_ENABLE_STATUS_DISABLED 0

#ifndef TRACE_EVENT_TIME
#define TRACE_EVENT_TIME (1 << 1)
#endif

#define KTRACEENABLE    _IOR('T', 0, struct ktrace_enable)
#define KTRACEGETBUFFD  _IOR('T', 1, int)
#define KTRACEGETFORMAT _IOWR('T', 2, struct ktrace_event_format)
#define KTRACEGETEVID   _IOWR('T', 3, struct ktrace_getevid_format)
#endif
