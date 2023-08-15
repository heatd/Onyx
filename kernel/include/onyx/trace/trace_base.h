/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_TRACE_BASE_H
#define _ONYX_TRACE_BASE_H

#include <onyx/clock.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/types.h>

#include <onyx/utility.hpp>

struct tracing_header
{
    u32 evtype;
    // Size of tracing record, including the header
    u16 size;
    u32 cpu;
    // Timestamp, in nanoseconds
    u64 ts;
} __packed;

#define __tracing_section __attribute__((section(".data.trace"), used, aligned(1)))

#define TRACE_EVENT_ENABLED (1 << 0)
#define TRACE_EVENT_TIME    (1 << 1)

#ifndef __TRACE_EVENT_DEFINED
struct trace_event
{
    const char* name;
    const char* category;
    const char* format;
    u16 evid;
    u16 flags;
};
#define __TRACE_EVENT_DEFINED
#endif

void __trace_write(u8* buf, size_t len);

template <typename Callable>
struct scope_guard
{
    Callable c_;
    scope_guard(Callable c) : c_{c}
    {
    }

    ~scope_guard()
    {
        c_();
    }
};

#define TRACE_EVENT_DURATION(name, ...)                                                 \
    u64 __trace_timestamp = trace_##name##_enabled() ? clocksource_get_time() : 0;      \
    scope_guard __PASTE(__trace_scope_guard,                                            \
                        __COUNTER__){[__trace_timestamp __VA_OPT__(, ) __VA_ARGS__]() { \
        if (__trace_timestamp)                                                          \
            trace_##name(__trace_timestamp __VA_OPT__(, ) __VA_ARGS__);                 \
    }};

#define TRACE_EVENT(name, ...)         \
    do                                 \
    {                                  \
        if (trace_##name##_enabled())  \
            trace_##name(__VA_ARGS__); \
    } while (0);

#endif
