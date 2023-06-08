/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/fnv.h>
#include <onyx/ktsan.h>
#include <onyx/scheduler.h>

#include "ktsan.h"

#define KT_THREAD_CHAINS     256
#define KT_THREAD_CHAIN_MASK (KT_THREAD_CHAINS - 1)
static struct spinlock hashlock;
static struct list_head hashtab[KT_THREAD_CHAINS];

void kt_init_thread_ht()
{
    for (auto &h : hashtab)
        INIT_LIST_HEAD(&h);
}

static void kt_add_thread(kt_thread *thr)
{
    scoped_lock g{hashlock};

    auto hash = fnv_hash(&thr->id, sizeof(thr->id)) & KT_THREAD_CHAIN_MASK;
    list_add_tail(&thr->list_node, &hashtab[hash]);
}

static void kt_remove_thread(kt_thread *thr)
{
    scoped_lock g{hashlock};

    list_remove(&thr->list_node);
}

kt_thread *kt_get_thread(unsigned int id)
{
    scoped_lock g{hashlock};

    auto hash = fnv_hash(&id, sizeof(id)) & KT_THREAD_CHAIN_MASK;
    auto hc = &hashtab[hash];
    list_for_every (hc)
    {
        struct kt_thread *thr = container_of(l, kt_thread, list_node);
        if (thr->id == id)
            return thr;
    }

    return nullptr;
}

int kt_create_thread(struct thread *t)
{
    auto thr = (struct kt_thread *) zalloc(sizeof(kt_thread));
    if (!thr)
        return -ENOMEM;

    thr->enabled = true;
    // TODO: Allocate these IDs internally. At the moment, this will break if we spawn enough
    // threads (> KTSAN_MAX_THREADS)
    thr->id = t->id;
    thr->log = kt_event_log_alloc();
    if (!thr->log)
    {
        free(thr);
        return -ENOMEM;
    }

    kt_event_log_init(thr->log);

    t->ktsan_thr = thr;

    auto curr = get_current_thread();

    if (curr && curr->ktsan_thr)
    {
        // Inherit the vector clock from the current thread
        kt_clk_set(&thr->clk, &curr->ktsan_thr->clk);
    }

    kt_add_thread(thr);

    return 0;
}

void kt_free_thread(struct thread *t)
{
    kt_remove_thread(t->ktsan_thr);
    free(t->ktsan_thr);
}

/**
 * @brief Get the number of races that happened in the current thread
 *
 * @return Number of races
 */
unsigned long kt_get_nr_races()
{
    auto thr = get_current_thread();
    return thr->ktsan_thr->nr_races;
}

/**
 * @brief Disable KTSAN reports. To be used internally in tests.
 *
 */
void kt_thr_disable_report()
{
    auto thr = get_current_thread();
    thr->ktsan_thr->flags |= KT_FLAG_NO_REPORT;
}

/**
 * @brief Enable KTSAN reports. To be used internally in tests
 *
 */
void kt_thr_enable_report()
{
    auto thr = get_current_thread();
    thr->ktsan_thr->flags &= ~KT_FLAG_NO_REPORT;
}

/**
 * @brief Enable KTSAN
 *
 */
void kt_thr_enable()
{
    auto thr = get_current_thread();
    thr->ktsan_thr->enabled = true;
}

/**
 * @brief Disable KTSAN
 *
 */
void kt_thr_disable()
{
    auto thr = get_current_thread();
    thr->ktsan_thr->enabled = false;
}
