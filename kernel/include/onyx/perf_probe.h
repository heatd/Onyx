/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PERF_PROBE_H
#define _ONYX_PERF_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <onyx/compiler.h>

#include <uapi/perf_probe.h>

struct registers;

__BEGIN_CDECLS

size_t stack_trace_get(unsigned long *stack, unsigned long *pcs, size_t nr_pcs);

__END_CDECLS

/**
 * @brief Check if CPU perf probing is enabled
 *
 * @return True if enabled, else false
 */
bool perf_probe_is_enabled();

/**
 * @brief Do a CPU perf probe
 *
 * @param regs Registers
 */
void perf_probe_do(struct registers *regs);

/**
 * @brief Check is wait perf probing is enabled
 *
 * @return True if enabled, else false
 */
bool perf_probe_is_enabled_wait();

/**
 * @brief Set up a wait probe. Called right before platform_yield()
 *
 * @param fge flame_graph_entry, stack allocated
 */
void perf_probe_setup_wait(struct flame_graph_entry *fge);

/**
 * @brief Commit the wait probe
 *
 * @param fge flame_graph_entry, stack allocated
 */
void perf_probe_commit_wait(const struct flame_graph_entry *fge);

/**
 * @brief Try to take a trace for the wait probe
 *
 * @param regs Registers
 */
void perf_probe_try_wait_trace(struct registers *regs);

#endif
