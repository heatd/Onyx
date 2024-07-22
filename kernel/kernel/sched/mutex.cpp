/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/mutex.h>
#include <onyx/panic.h>
#include <onyx/rcupdate.h>
#include <onyx/scheduler.h>
#include <onyx/scoped_lock.h>
#include <onyx/task_switching.h>
#include <onyx/thread.h>

/*
struct mutex
{
    struct spinlock llock;
    struct list_head waiters;
    unsigned long counter;
};
*/
#define MUTEX_LOCKED      (1 << 0)
#define MUTEX_HAS_WAITERS (1 << 1)
#define MUTEX_FLAGS       (MUTEX_LOCKED | MUTEX_HAS_WAITERS)

static unsigned long thread_to_lock_word(thread *t)
{
    return ((unsigned long) t | MUTEX_LOCKED);
}

static thread *lock_word_to_thread(unsigned long word)
{
    return (thread *) (word & ~MUTEX_FLAGS);
}

thread *mutex_owner(mutex *mtx)
{
    auto counter = read_once(mtx->counter);
    return (!(counter & MUTEX_LOCKED) ? nullptr : lock_word_to_thread(counter));
}

#define MUTEX_WAITER_QUEUED (1 << 0)

struct mutex_waiter
{
    struct thread *thread;
    struct list_head list_node;
    unsigned short flags;
};

/**
 * @brief Version of mutex_trylock that handles contended mutexes
 *
 * @param lock Lock
 * @return true if acquired, else false
 */
static bool __mutex_trylock(mutex *lock)
{
    /* When faced with a conteded mutex, attempt to lock it while keeping the MUTEX_HAS_WAITERS
     * flag. This is palpably unfair to other waiters if we've just arrived. Oh well.
     */
    unsigned long expected, to_write;
    do
    {
        expected = __atomic_load_n(&lock->counter, __ATOMIC_RELAXED);
        if (expected & MUTEX_LOCKED)
            return false;
        to_write = thread_to_lock_word(get_current_thread()) | (expected & MUTEX_HAS_WAITERS);
    } while (!__atomic_compare_exchange_n(&lock->counter, &expected, to_write, false,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));
    return true;
}

__always_inline bool __mutex_trylock_fastpath(mutex *lock)
{
    unsigned long expected = 0;
    auto word = thread_to_lock_word(get_current_thread());
    return __atomic_compare_exchange_n(&lock->counter, &expected, word, false, __ATOMIC_ACQUIRE,
                                       __ATOMIC_RELAXED);
}

static bool mutex_spin(mutex *lock)
{
    /* The algorithm goes like this: Try to always fetch the owner thread,
     * and if there's none try to acquire the lock. If in fact there is a thread,
     * check if it's on the same CPU; if so, give up, if not, try to get the lock.
     * RCU protects us here from threads going away.
     */
    rcu_read_lock();
    bool success = false;
    struct thread *current = get_current_thread();

    for (;;)
    {
        auto thread = mutex_owner(lock);

        if (!thread)
        {
            success = __mutex_trylock(lock);
            break;
        }

        /* Check if the thread is indeed running */
        if (!(__atomic_load_n(&thread->flags, __ATOMIC_RELAXED) & THREAD_RUNNING))
            break;

        /* If *we* need to resched, stop wasting CPU time (and RCU wouldn't preempt us anyway...) */
        if (sched_needs_resched(current))
            break;

        cpu_relax();
    }

    rcu_read_unlock();

    return success;
}

bool mutex_trylock(mutex *lock)
{
    return __mutex_trylock_fastpath(lock) || __mutex_trylock(lock);
}

static void mutex_prepare_sleep(struct mutex *mutex, int state, struct mutex_waiter *waiter)
{
    MUST_HOLD_LOCK(&mutex->llock);
    set_current_state(state);
    DCHECK(!(waiter->flags & MUTEX_WAITER_QUEUED));

    if (!(waiter->flags & MUTEX_WAITER_QUEUED))
    {
        if (list_is_empty(&mutex->waiters))
            __atomic_or_fetch(&mutex->counter, MUTEX_HAS_WAITERS, __ATOMIC_RELEASE);

        list_add_tail(&waiter->list_node, &mutex->waiters);
        waiter->flags |= MUTEX_WAITER_QUEUED;
    }
}

int mutex_lock_slow_path(struct mutex *mutex, int state)
{
    int ret = 0;
    bool signals_allowed = state == THREAD_INTERRUPTIBLE;
    struct thread *current = get_current_thread();

    struct mutex_waiter waiter;
    waiter.thread = current;
    waiter.flags = 0;

    auto owner = mutex_owner(mutex);
    assert(owner != current);

    /* Lock the queue, prepare the sleep, try one more time. If we can't get the lock, sleep. */
    while (true)
    {
        spin_lock(&mutex->llock);
        mutex_prepare_sleep(mutex, state, &waiter);

        if (__mutex_trylock(mutex))
            break;

        if (signals_allowed && signal_is_pending())
        {
            ret = -EINTR;
            break;
        }

        spin_unlock(&mutex->llock);

        sched_yield();
        /* We (may) have slept, try again (and try to spin, again) */
        if (__mutex_trylock(mutex) || mutex_spin(mutex))
        {
            /* Check if we're still queued, if so, the exit path will take care of it */
            if (waiter.flags & MUTEX_WAITER_QUEUED)
            {
                spin_lock(&mutex->llock);
                /* Re-check under the lock, since wakers only touch it with this lock held. */
                if (!(waiter.flags & MUTEX_WAITER_QUEUED))
                    spin_unlock(&mutex->llock);
            }

            break;
        }
    }

    if (waiter.flags & MUTEX_WAITER_QUEUED)
    {
        /* Note: If this condition is true, we *know* we hold llock */
        list_remove(&waiter.list_node);
        /* While here, check if the list is now empty, and if so clear the waiters flag */
        if (list_is_empty(&mutex->waiters))
            __atomic_and_fetch(&mutex->counter, ~MUTEX_HAS_WAITERS, __ATOMIC_RELEASE);
        spin_unlock(&mutex->llock);
    }

    set_current_state(THREAD_RUNNABLE);

    return ret;
}

static inline void mutex_postlock(mutex *mtx)
{
}

__always_inline int __mutex_lock(struct mutex *mutex, int state)
    ACQUIRE(mutex) NO_THREAD_SAFETY_ANALYSIS
{
    MAY_SLEEP();
    int ret = 0;
    if (!mutex_trylock(mutex)) [[unlikely]]
        if (!mutex_spin(mutex)) [[unlikely]]
            ret = mutex_lock_slow_path(mutex, state);

    if (ret >= 0) [[likely]]
        mutex_postlock(mutex);

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

[[gnu::noinline]] void mutex_unlock_wake(struct mutex *mutex)
{
    scoped_lock g{mutex->llock};

    if (!list_is_empty(&mutex->waiters))
    {
        struct list_head *l = list_first_element(&mutex->waiters);
        mutex_waiter *w = container_of(l, mutex_waiter, list_node);
        list_remove(&w->list_node);
        w->flags = 0;
        thread_wake_up(w->thread);

        if (list_is_empty(&mutex->waiters))
            __atomic_and_fetch(&mutex->counter, ~MUTEX_HAS_WAITERS, __ATOMIC_RELEASE);
    }
}

void mutex_unlock(struct mutex *mutex) NO_THREAD_SAFETY_ANALYSIS
{
    unsigned long word = __atomic_and_fetch(&mutex->counter, MUTEX_HAS_WAITERS, __ATOMIC_RELEASE);
    if (word & MUTEX_HAS_WAITERS) [[unlikely]]
        mutex_unlock_wake(mutex);
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
