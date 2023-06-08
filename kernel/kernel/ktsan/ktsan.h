/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_KTSAN_H
#define _ONYX_KTSAN_H

#include <string.h>

#include <onyx/compiler.h>
#include <onyx/irq.h>
#include <onyx/list.h>
#include <onyx/scheduler.h>
#include <onyx/types.h>

#include "spinlock.h"

#include <onyx/pair.hpp>

/* Note: All of this work is inspired by LLVM's TSAN implementation, and the old
 * google/kernel-sanitizer KTSAN patches (which themselves are very similar to LLVM TSAN).
 * The concepts remain mostly similar.
 */

enum ktsan_memory_order
{
    ktsan_memory_order_relaxed,
    ktsan_memory_order_acquire,
    ktsan_memory_order_release,
    ktsan_memory_order_acq_rel
};

typedef unsigned long kt_time_t;

#define KTSAN_MAX_THREADS 1024

struct kt_clock
{
    kt_time_t time[KTSAN_MAX_THREADS];
};

__always_inline void kt_clk_inc(kt_clock *clk, u32 id)
{
    clk->time[id]++;
}

__always_inline kt_time_t kt_clk_get(kt_clock *clk, u32 id)
{
    return clk->time[id];
}

void kt_init_thread_ht();

struct kt_event_log;

struct kt_thread
{
    kt_clock clk;
    // TODO(pedro): Remove this after testing?
    bool enabled;
    // TODO(pedro): mutex set?
    unsigned long nr_races;
    unsigned int flags;
    unsigned int id;
    // Number of nested TSAN calls. If 1, do not enter ktsan code
    unsigned int nested_tsan;
    kt_event_log *log;
    struct list_head list_node;
};

#define KT_FLAG_NO_REPORT (1U << 0)

/**
 * @brief Get the number of races that happened in the current thread
 *
 * @return Number of races
 */
unsigned long kt_get_nr_races();

/**
 * @brief Disable KTSAN reports. To be used internally in tests.
 *
 */
void kt_thr_disable_report();

/**
 * @brief Enable KTSAN reports. To be used internally in tests
 *
 */
void kt_thr_enable_report();

/**
 * @brief Enable KTSAN
 *
 */
void kt_thr_enable();

/**
 * @brief Disable KTSAN
 *
 */
void kt_thr_disable();

/* KTSAN requires a shadow map for memory. This shadow map will store data for accesses to memory.
 * We'll pick 4 entries for each 8 bytes.
 */
#define KTSAN_SHADOW_SLOTS_LOG 2

#define KTSAN_SHADOW_SLOTS (1UL << KTSAN_SHADOW_SLOTS_LOG)

#define KT_TID_BITS   12
#define KT_CLOCK_BITS 42

union kt_shadow {
    struct
    {
        unsigned long tid : KT_TID_BITS;
        unsigned long clock : KT_CLOCK_BITS;
        unsigned long write : 1;
        unsigned long atomic : 1;
        unsigned long size : 2;
        unsigned long offset : 3;
    };
    u64 word;
};

kt_shadow *kt_get_shadow(void *addr);

void kt_clk_acquire(kt_clock *dest, kt_clock *src);
void kt_clk_set(kt_clock *dest, kt_clock *src);

/**
 * @brief Helps synchronize vector clocks between threads.
 * On ACQUIRE atomic operations/mutex ops, we set our thraad's vector clock
 * using kt_clk_acquire. On release, we set the sync object's vector clock using
 * kt_clk_acquire. This models memory ordering consistency on locks/atomics.
 * The sync objects remain in a hashtable, are hashed by address and are created on-demand.
 */
struct kt_sync_obj
{
    kt_spinlock lock;
    struct list_head node;
    kt_clock clk;
    unsigned long addr;
};

static inline void kt_sync_init(kt_sync_obj *obj, kt_thread *thr)
{
    memset(obj, 0, sizeof(*obj));
    kt_clk_set(&obj->clk, &thr->clk);
}

void kt_sync_acquire(kt_sync_obj *sobj, kt_thread *thr);
void kt_sync_release(kt_sync_obj *sobj, kt_thread *thr);

kt_sync_obj *kt_sync_alloc();

void kt_sync_free(kt_sync_obj *obj);
void kt_init_sync_cache();

/**
 * @brief Find or create a sync object
 *
 * @param addr Address of the sync object
 * @param thr Current kt_thread
 * @return A pointer to the kt_sync_obj, and a bool 'created'
 */
cul::pair<kt_sync_obj *, bool> kt_sync_find_or_create(unsigned long addr, kt_thread *thr);

__always_inline kt_thread *ktsan_enter()
{
    auto thr = get_current_thread();
    // TODO: Instrument interrupts too?
    if (!thr || is_in_interrupt() || irq_is_disabled()) [[unlikely]]
        return nullptr;
    auto kt = thr->ktsan_thr;
    if (!kt) [[unlikely]]
        return nullptr;
    if (!kt->enabled) [[unlikely]]
        return nullptr;

    if (kt->nested_tsan > 0) [[unlikely]]
        return nullptr;
    kt->nested_tsan++;

    return kt;
}

__always_inline void ktsan_exit(kt_thread *thr)
{
    if (thr)
        thr->nested_tsan--;
}

void kt_clear_shadow_one(unsigned long addr);

#define KT_EVENT_DATA(event) ((event) & ((1UL << 48) - 1))

#define KT_NR_EVENTS_LOG  0x10000
#define KT_EVENT_LOG_MASK (KT_NR_EVENTS_LOG - 1)

struct kt_event_log
{
    u64 buf[KT_NR_EVENTS_LOG];
    u32 rd;
    u32 wr;
    spinlock lock;

    bool full() const
    {
        return wr - rd == KT_NR_EVENTS_LOG;
    }

    bool empty() const
    {
        return wr == rd;
    }

    void write(u64 data)
    {
        if (full())
        {
            rd++;
            assert(!full());
        }

        const size_t wr_index = wr & KT_EVENT_LOG_MASK;
        // Write until the first obstacle
        buf[wr_index] = data;
        wr++;
    }
};

kt_event_log *kt_event_log_alloc();

static inline void kt_event_log_init(struct kt_event_log *log)
{
    log->rd = log->wr = 0;
    spinlock_init(&log->lock);
}

static inline void kt_event_log_write(struct kt_thread *thread, u16 type, u64 data)
{
    auto log = thread->log;
    scoped_lock g{log->lock};

    log->write((u64) type << 48 | data);

    // Note: Each event increments the clock implicitly
    kt_clk_inc(&thread->clk, thread->id);
}

#define KT_EVENT_FUNC_ENTRY 1
#define KT_EVENT_FUNC_EXIT  2
#define KT_EVENT_ACCESS     3
#define KT_EVENT_MTX_LOCK   4
#define KT_EVENT_MTX_UNLOCK 5

__always_inline u64 kt_compress_ptr(void *ptr)
{
    // To be able to store these in the event log, we need to compress the pointer
    // into 48-bits. Thankfully, x86_64 has 48-bits.
    // XXX this is not portable
    return (u64) ptr & ((1UL << 48) - 1);
}

__always_inline void *kt_decompress_ptr(u64 ptr_val)
{
    // XXX this is not portable
    return (void *) (ptr_val | (0xffffUL << 48));
}

kt_thread *kt_get_thread(unsigned int id);

#define KT_STACK_NR_PCS 64

struct kt_stack
{
    u32 size;
    u64 pcs[64];
};

void kt_event_log_replay_stack(struct kt_event_log *log, u64 clock, u16 expected_event_type,
                               u64 expected_data, kt_stack *stack);

#endif
