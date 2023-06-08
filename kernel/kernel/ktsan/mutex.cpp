/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/ktsan.h>

#include "ktsan.h"

void kt_mutex_post_lock(void *ptr)
{
    auto thr = ktsan_enter();
    if (!thr)
        return;

    auto [so, created] = kt_sync_find_or_create((unsigned long) ptr, thr);

    if (!so)
        return;

    kt_event_log_write(thr, KT_EVENT_MTX_LOCK, kt_compress_ptr(ptr));

    kt_sync_acquire(so, thr);
    // printk("acq clk 15 %lu clk 16 %lu\n", kt_clk_get(&thr->clk, 15), kt_clk_get(&thr->clk, 16));

    ktsan_exit(thr);
}

void kt_mutex_pre_release(void *ptr)
{
    auto thr = ktsan_enter();
    if (!thr)
        return;

    auto [so, created] = kt_sync_find_or_create((unsigned long) ptr, thr);

    if (!so)
        return;

    kt_event_log_write(thr, KT_EVENT_MTX_UNLOCK, kt_compress_ptr(ptr));

    kt_sync_release(so, thr);

    // printk("rel clk 15 %lu clk 16 %lu\n", kt_clk_get(&thr->clk, 15), kt_clk_get(&thr->clk, 16));

    ktsan_exit(thr);
}
