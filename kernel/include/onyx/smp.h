/*
 * Copyright (c) 2019 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _CARBON_SMP_H
#define _CARBON_SMP_H

#include <stddef.h>

#include <onyx/limits.h>
#include <onyx/percpu.h>

#ifdef __cplusplus

#include <onyx/cpumask.h>

namespace smp
{

void set_number_of_cpus(unsigned int nr);
void set_online(unsigned int cpu);
void boot(unsigned int cpu);
unsigned int get_online_cpus();

void boot_cpus();

using sync_call_func = void (*)(void *context);

/**
 * @brief Calls f on every CPU
 *
 * @param f The function to call on every cpu
 * @param context Context to get passed to f
 * @param mask Mask of cpus that will execute this
 */
void sync_call(sync_call_func f, void *context, const cpumask &mask);

/**
 * @brief Calls f on every CPU, and calls local on the local CPU
 *
 * @param f The function to call on every cpu
 * @param context Context to get passed to f
 * @param mask Mask of cpus that will execute this
 * @param local The function to get called on this cpu
 * @param context2 The context for the local function
 */
void sync_call_with_local(sync_call_func f, void *context, const cpumask &mask,
                          sync_call_func local, void *context2);

void cpu_handle_sync_calls();

cpumask get_online_cpumask();

}; // namespace smp
#endif

struct smp_header
{
    volatile unsigned long thread_stack;
    volatile unsigned long boot_done;
    volatile unsigned long kernel_load_bias;
} __attribute__((packed));

#ifdef __cplusplus
extern "C"
{
#endif

/* We define CPU_MAX as UINT_MAX - 1, because we use unsigned ints to represent CPU numbers
 * and as such, we'll always have 1 less available to represent CPU0.
 */
#define CPU_MAX     (UINT_MAX - 1)
#define MAX_NR_CPUS UINT_MAX

extern unsigned int cpu_nr;

__attribute__((always_inline)) static inline unsigned int get_cpu_nr()
{
    return get_per_cpu(cpu_nr);
}

void smp_parse_cpus(void *madt);
void smp_boot_cpus();

#ifdef __cplusplus
}
#endif

#endif
