/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/cpu.h>
#include <onyx/ktsan.h>
#include <onyx/kunit.h>
#include <onyx/scheduler.h>

#include "ktsan.h"

TEST(ktsan, shadow_works)
{
    // Check that our current stack is shadowed, and that shadow calculation is being done
    // properly
    unsigned long arr[2];
    auto shadow1 = kt_get_shadow(arr);
    ASSERT_NONNULL(shadow1);
    EXPECT_TRUE(((unsigned long) shadow1 & (sizeof(kt_shadow) - 1)) == 0);
    EXPECT_EQ(shadow1 + KTSAN_SHADOW_SLOTS, kt_get_shadow(&arr[1]));
}

TEST(ktsan, test_simple_race)
{
    // TODO(pedro): Once KTSAN is stable, remove all the explicit enables/disables
    kt_thr_disable_report();
    auto nr_races = kt_get_nr_races();
    // Test if a simple thread race gets detected
    struct test_struct
    {
        int var;
        unsigned long remote_races;
    };

    test_struct s;
    s.var = 0;
    s.remote_races = ULONG_MAX;

    auto thread = sched_create_thread(
        [](void *ctx) {
            kt_thr_disable_report();
            kt_thr_enable();
            test_struct *ptr = (test_struct *) ctx;
            if (ptr->var == 0)
                ptr->var = 10;
            kt_thr_disable();
            __atomic_store_n(&ptr->remote_races, kt_get_nr_races(), __ATOMIC_RELEASE);
        },
        THREAD_KERNEL, &s);

    sched_start_thread(thread);

    kt_thr_enable();

    if (s.var == 0)
        s.var = 11;

    // Wait for the remote races to be stored
    while (__atomic_load_n(&s.remote_races, __ATOMIC_ACQUIRE) == ULONG_MAX)
        cpu_relax();

    kt_thr_disable();

    EXPECT_GE(1ul, s.remote_races);
    EXPECT_GE(1ul, kt_get_nr_races() - nr_races);
}

TEST(ktsan, test_simple_race_overlap)
{
    // TODO(pedro): Once KTSAN is stable, remove all the explicit enables/disables
    kt_thr_disable_report();
    auto nr_races = kt_get_nr_races();
    // Test if an overlap gets properly detected
    struct test_struct
    {
        union {
            int word;
            char bytes[4];
        } var;
        unsigned long remote_races;
    };

    test_struct s;
    s.var.word = 0;
    s.remote_races = ULONG_MAX;

    // Make sure the shadow is clear from previous racy accesses in previous tests
    kt_clear_shadow_one((unsigned long) &s.var.word);
    auto thread = sched_create_thread(
        [](void *ctx) {
            kt_thr_disable_report();
            kt_thr_enable();
            test_struct *ptr = (test_struct *) ctx;
            if (ptr->var.bytes[3] == 0)
                ptr->var.bytes[3] = 10;
            kt_thr_disable();
            __atomic_store_n(&ptr->remote_races, kt_get_nr_races(), __ATOMIC_RELEASE);
        },
        THREAD_KERNEL, &s);

    sched_start_thread(thread);

    kt_thr_enable();

    if (s.var.word == 0)
        s.var.word = 11;

    // Wait for the remote races to be stored
    while (__atomic_load_n(&s.remote_races, __ATOMIC_ACQUIRE) == ULONG_MAX)
        cpu_relax();

    kt_thr_disable();

    auto total_races = s.remote_races + kt_get_nr_races() - nr_races;
    EXPECT_LE(1ul, total_races);
}

#if 0
// TODO: Sync object unit test
TEST(ktsan, sync_obj_vector_clock_works)
{
    kt_sync_obj obj;
    auto curr_kthr = get_current_thread()->ktsan_thr;
    kt_sync_init(&obj, curr_kthr);
    for (unsigned long i = 0)
}

#endif

TEST(ktsan, sync_obj_no_race)
{
    // TODO(pedro): Once KTSAN is stable, remove all the explicit enables/disables
    kt_thr_disable_report();
    auto nr_races = kt_get_nr_races();
    // Test if the sync object + spinlock removes the race
    struct test_struct
    {
        union {
            int word;
            char bytes[4];
        } var;
        struct spinlock lock;
        unsigned long remote_races;
    };

    test_struct s;
    s.var.word = 0;
    s.remote_races = ULONG_MAX;

    // Make sure the shadow is clear from previous racy accesses in previous tests
    kt_clear_shadow_one((unsigned long) &s.var.word);
    spinlock_init(&s.lock);

    // The spinlock's sync object's clock will get initialized with the current clock
    // On acquire, current->clk[i] = max(sync[i], current->clk[i]). This works to model
    // memory ordering consistency between __ATOMIC_ACQUIRE and __ATOMIC_RELEASE.
    // On release, sync[i] = max(sync[i], current->clk[i]); so writes get "posted" to the next
    // acquirer.

    auto thread = sched_create_thread(
        [](void *ctx) {
            kt_thr_disable_report();
            kt_thr_enable();
            test_struct *ptr = (test_struct *) ctx;

            spin_lock(&ptr->lock);

            if (ptr->var.bytes[3] == 0)
                ptr->var.bytes[3] = 10;

            spin_unlock(&ptr->lock);
            kt_thr_disable();
            __atomic_store_n(&ptr->remote_races, kt_get_nr_races(), __ATOMIC_RELEASE);
        },
        THREAD_KERNEL, &s);

    sched_start_thread(thread);

    kt_thr_enable();

    spin_lock(&s.lock);
    if (s.var.word == 0)
        s.var.word = 11;

    spin_unlock(&s.lock);

    // Wait for the remote races to be stored
    while (__atomic_load_n(&s.remote_races, __ATOMIC_ACQUIRE) == ULONG_MAX)
        cpu_relax();

    kt_thr_disable();

    EXPECT_EQ(0ul, s.remote_races);
    EXPECT_EQ(0ul, kt_get_nr_races() - nr_races);
}
