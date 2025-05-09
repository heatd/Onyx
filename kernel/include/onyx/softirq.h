/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_SOFTIRQ_H
#define _ONYX_SOFTIRQ_H

#include <onyx/compiler.h>
#include <onyx/percpu.h>

enum softirq_vector
{
    SOFTIRQ_VECTOR_TIMER = 0,
    SOFTIRQ_VECTOR_NETRX,
    SOFTIRQ_VECTOR_TASKLET,
    SOFTIRQ_VECTOR_BLOCK,
    SOFTIRQ_VECTOR_RCU,
    SOFTIRQ_VECTOR_MAX
};

__BEGIN_CDECLS

struct seq_file;
void softirq_print_stat(struct seq_file *m);
void softirq_raise(enum softirq_vector vec);
bool softirq_pending();
void softirq_handle();

extern bool handling_softirq;

__always_inline __nocov bool softirq_is_handling()
{
    return get_per_cpu(handling_softirq);
}

__END_CDECLS

#endif
