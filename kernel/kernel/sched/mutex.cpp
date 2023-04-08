/*
 * Copyright (c) 2020 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/mutex.h>
#include <onyx/panic.h>
#include <onyx/scheduler.h>
#include <onyx/scoped_lock.h>
#include <onyx/task_switching.h>
#include <onyx/thread.h>

static unsigned long thread_to_lock_word(thread *t)
{
    return (unsigned long) t ^ 1;
}

static thread *lock_word_to_thread(unsigned long word)
{
    return (thread *) (word ^ 1);
}

thread *mutex_owner(mutex *mtx)
{
    auto counter = read_once(mtx->counter);
    return (counter == 0 ? nullptr : lock_word_to_thread(counter));
}

static void mutex_prepare_sleep(struct mutex *mtx, int state)
{
    scoped_lock g{mtx->llock};

    thread *t = get_current_thread();

    set_current_state(state);

    list_add_tail(&t->wait_list_head, &mtx->thread_list);
}

static void mutex_dequeue_thread(mutex *mtx, thread *thr)
{
    scoped_lock g{mtx->llock};
    list_remove(&thr->wait_list_head);
}

bool __mutex_trylock(mutex *lock)
{
    unsigned long expected = 0;
    auto word = thread_to_lock_word(get_current_thread());
    return __atomic_compare_exchange_n(&lock->counter, &expected, word, false, __ATOMIC_ACQUIRE,
                                       __ATOMIC_RELAXED);
}

bool mutex_optimistic_spin(mutex *lock)
{
    /* The algorithm goes like this: Try to always fetch the owner thread,
     * and if there's none try to acquire the lock. If in fact there is a thread,
     * check if it's on the same CPU; if so, give up, if not, try to get the lock
     * until we run out of budget. If the thread changes from under us, give up too.
     */
    thread *last_thread = nullptr;
    for (int i = 0; i < 500; i++)
    {
        auto thread = mutex_owner(lock);

        if (!thread)
            return __mutex_trylock(lock);

        if (last_thread && thread != last_thread)
            return false;

        if (thread->cpu == get_cpu_nr())
            return false;

        last_thread = thread;

        cpu_relax();
    }

    return false;
}

bool mutex_trylock(mutex *lock)
{
    return __mutex_trylock(lock) || mutex_optimistic_spin(lock);
}

static void commit_sleep(void)
{
    sched_yield();
}

int mutex_lock_slow_path(struct mutex *mutex, int state)
{
    int ret = 0;
    bool signals_allowed = state == THREAD_INTERRUPTIBLE;

    struct thread *current = get_current_thread();

    mutex_prepare_sleep(mutex, state);

    while (!mutex_trylock(mutex))
    {
        if (signals_allowed && signal_is_pending())
        {
            ret = -EINTR;
            break;
        }

        auto owner = mutex_owner(mutex);

        assert(owner != current);

        commit_sleep();

        mutex_dequeue_thread(mutex, current);

        mutex_prepare_sleep(mutex, state);
    }

    set_current_state(THREAD_RUNNABLE);

    mutex_dequeue_thread(mutex, current);

    return ret;
}

static inline void mutex_postlock(mutex *mtx)
{
}

int __mutex_lock(struct mutex *mutex, int state)
{
    MAY_SLEEP();
    int ret = 0;
    if (!mutex_trylock(mutex)) [[unlikely]]
        ret = mutex_lock_slow_path(mutex, state);

    if (ret >= 0) [[likely]]
    {
        mutex_postlock(mutex);
    }

    return ret;
}

void mutex_lock(struct mutex *mutex)
{
    __mutex_lock(mutex, THREAD_UNINTERRUPTIBLE);
}

int mutex_lock_interruptible(struct mutex *mutex)
{
    return __mutex_lock(mutex, THREAD_INTERRUPTIBLE);
}

void mutex_unlock(struct mutex *mutex)
{
    // MAY_SLEEP();
    __atomic_store_n(&mutex->counter, 0, __ATOMIC_RELEASE);

    scoped_lock g{mutex->llock};

    if (!list_is_empty(&mutex->thread_list))
    {
        struct list_head *l = list_first_element(&mutex->thread_list);
        assert(l != &mutex->thread_list);
        struct thread *t = container_of(l, struct thread, wait_list_head);

        thread_wake_up(t);
    }
}

bool mutex_holds_lock(struct mutex *m)
{
    return m->counter && mutex_owner(m) == get_current_thread();
}

#ifdef CONFIG_KTEST_MUTEX

#include <stdio.h>

#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/scoped_lock.h>

#include <libtest/libtest.h>

static DECLARE_MUTEX(mtx) = {};

static volatile unsigned long counter = 0;

static unsigned int mtx_completed = 0;
static thread *to_wake_up = nullptr;

void mutex_thread_entry(void *arg)
{
    bool incs = (unsigned int) (unsigned long) arg % 2;
    for (long i = 0; i < 0xffffff; i++)
    {
        {
            scoped_mutex g{mtx};

            if (incs)
                counter = counter + 1;
            else
                counter = counter - 1;
        }

        for (int i = 0; i < 1; i++)
            cpu_relax();

        // sched_sleep(10);
    }

    mtx_completed++;

    thread_wake_up(to_wake_up);

    thread_exit();
}

bool mutex_test(void)
{
    counter = 0;
    mtx_completed = 0;
    to_wake_up = get_current_thread();
    auto clock = get_main_clock();

    auto t0 = clock->get_ns();

    mutex_init(&mtx);

    for (unsigned int i = 0; i < 4; i++)
    {
        auto thread =
            sched_create_thread(mutex_thread_entry, THREAD_KERNEL, (void *) (unsigned long) i);

        assert(thread != nullptr);

        sched_start_thread(thread);
    }

    sched_block(get_current_thread());

    while (mtx_completed != 4)
        cpu_relax();

    auto t1 = clock->get_ns();

    printk("mutex test completed in %lu ns\n", t1 - t0);

    return counter == 0;
}

DECLARE_TEST(mutex_test, 4);

#endif
