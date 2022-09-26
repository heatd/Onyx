/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_PUBLIC_PERF_PROBE_H
#define _ONYX_PUBLIC_PERF_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FLAME_GRAPH_FRAMES   32
#define FLAME_GRAPH_NENTRIES 65536

struct flame_graph_entry
{
    unsigned long rips[FLAME_GRAPH_FRAMES];
};

struct flame_graph_pcpu
{
    uint32_t nentries;
    uint32_t windex;
    struct flame_graph_entry *fge; /* array of nentries */
    int dummy[12];
};

#define PERF_PROBE_ENABLE_DISABLE_CPU  0
#define PERF_PROBE_GET_BUFFER_LENGTH   1
#define PERF_PROBE_READ_DATA           2
#define PERF_PROBE_ENABLE_DISABLE_WAIT 3

#endif
