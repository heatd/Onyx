/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_PUBLIC_KCOV_H
#define _ONYX_PUBLIC_KCOV_H

#include <sys/ioctl.h>

#include <onyx/types.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE     _IO('c', 100)
#define KCOV_DISABLE    _IO('c', 101)

enum kcov_tracing_mode
{
    KCOV_TRACING_NONE = -1,
    KCOV_TRACING_TRACE_PC = 0,
    KCOV_TRACING_MAX
};

#endif
