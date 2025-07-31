/*
 * Copyright (c) 2017 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>

#include <onyx/cpu.h>
#include <onyx/rwlock.h>
#include <onyx/scheduler.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>
#include <onyx/thread.h>
#include <onyx/types.h>

#include "primitive_generic.h"

__always_inline unsigned long thread_to_counter(thread *t)
{
    unsigned long c = (unsigned long) t;
    DCHECK((c & 3) == 0);
    return c >> 2;
}

__always_inline thread *counter_to_thread(unsigned long c)
{
    return (thread *) (c << 2);
}

#define RW_WAITER_WRITER (1U << 0)
#define RW_WAITER_QUEUED (1U << 1)
/**
 * @brief Represents a waiter in the wait queue
 *
 */
struct rwlock_waiter
{
    struct list_head head;
    thread *thr;
    u8 flags;

    rwlock_waiter(thread *curr, u8 flags) : thr{curr}, flags{flags}
    {
    }
};

int rw_lock_tryread(rwlock *lock)
{
    unsigned long l;
    unsigned long to_insert;

    do
    {
        l = __atomic_load_n(&lock->lock, __ATOMIC_RELAXED);

        if (l & RDWR_LOCK_WRITE) [[unlikely]]
            return -EAGAIN;

        if (l == RDWR_MAX_COUNTER) [[unlikely]]
            return -EAGAIN;

        to_insert = l + 1;
    } while (!__atomic_compare_exchange_n(&lock->lock, &l, to_insert, false, __ATOMIC_ACQUIRE,
                                          __ATOMIC_RELAXED));

    return 0;
}

int rw_lock_trywrite(rwlock *lock)
{
    unsigned long expected;
    unsigned long write_value;
    const auto counter_val = thread_to_counter(get_current_thread());

    do
    {
        expected = __atomic_load_n(&lock->lock, __ATOMIC_RELAXED);
        write_value = RDWR_LOCK_WRITE | counter_val;

        if (expected & (RDWR_LOCK_WRITE | RDWR_LOCK_COUNTER_MASK))
            return false;
        if (expected & RDWR_LOCK_WAITERS)
            write_value |= RDWR_LOCK_WAITERS;
    } while (!__atomic_compare_exchange_n(&lock->lock, &expected, write_value, false,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));

    return true;
}

__always_inline void rwlock_prepare_sleep(rwlock *rwl, rwlock_waiter *w, int state)
{
    MUST_HOLD_LOCK(&rwl->llock);
    set_current_state(state);

    if (!(w->flags & RW_WAITER_QUEUED))
    {
        // A writer lock behaves exactly like an exclusive entry.
        // When wake-up code sees a writer, it stops right there and then.
        // Therefore, add it to the tail, while we add readers to the head.
        // TODO: This may be super unfair. Get feedback from mjg and/or read more
        // about rwlock fairness.
        if (w->flags & RW_WAITER_WRITER)
            list_add_tail(&w->head, &rwl->waiting_list);
        else
            list_add(&w->head, &rwl->waiting_list);
        w->flags |= RW_WAITER_QUEUED;
    }

    __atomic_or_fetch(&rwl->lock, RDWR_LOCK_WAITERS, __ATOMIC_ACQUIRE);
}

__always_inline void dequeue_thread_rwlock(rwlock *lock, rwlock_waiter *w)
{
    MUST_HOLD_LOCK(&lock->llock);
    list_remove(&w->head);
    w->flags &= ~RW_WAITER_QUEUED;
}

int rwspin_succ = 0;
int rwspin_fail = 0;

__always_inline bool rw_lock_spin_write(rwlock *lock)
{
    /* The algorithm goes like this: Try to always fetch the owner thread,
     * and if there's none try to acquire the lock. If in fact there is a thread,
     * check if it's on the same CPU; if so, give up, if not, try to get the lock
     * until we run out of budget. If the thread changes from under us, give up too.
     */
    for (;;)
    {
        // Stop spinning if it's not write locked
        const auto counter = read_once(lock->lock);
        if (counter != RDWR_LOCK_WRITE && counter != 0)
            return rwspin_fail++, false;

        struct thread *thread = counter_to_thread(counter);

        if ((counter & RDWR_LOCK_COUNTER_MASK) == 0)
        {
            if (rw_lock_trywrite(lock)) [[likely]]
                return rwspin_succ++, true;
        }

        if (thread && !(thread->flags & THREAD_RUNNING))
            return rwspin_fail++, false;

        cpu_relax();
    }
}

__always_inline bool rw_lock_spin_read(rwlock *lock)
{
    /* The algorithm goes like this: Try to always fetch the owner thread,
     * and if there's none try to acquire the lock. If in fact there is a thread,
     * check if it's on the same CPU; if so, give up, if not, try to get the lock
     * until we run out of budget. If the thread changes from under us, give up too.
     */
    for (;;)
    {
        // Stop spinning if it's not write locked
        const auto counter = read_once(lock->lock);
        struct thread *thread = counter_to_thread(counter);

        if (!(counter & RDWR_LOCK_WRITE))
        {
            if (rw_lock_tryread(lock) == 0) [[likely]]
                return rwspin_succ++, true;
        }

        if (thread && !(thread->flags & THREAD_RUNNING))
            return rwspin_fail++, false;

        cpu_relax();
    }
}

__noinline int __rw_lock_write_slow(rwlock *lock, int state)
{
    int ret = 0;
    thread *current = get_current_thread();
    const bool signals_allowed = state == THREAD_INTERRUPTIBLE;

    DCHECK(counter_to_thread(read_once(lock->lock)) != current);

    /**
     * Slow path algorithm:
     * First, lock the queue and queue ourselves in. Then, under the lock, try again. If we fail,
     * unlock and try to sleep. After we wake up, try again. *IF* we fail, restart.
     */
    rwlock_waiter w{current, RW_WAITER_WRITER};
    while (true)
    {
        spin_lock(&lock->llock);
        rwlock_prepare_sleep(lock, &w, state);

        if (rw_lock_trywrite(lock))
            break;

        if (signals_allowed && signal_is_pending())
        {
            ret = -EINTR;
            break;
        }

        spin_unlock(&lock->llock);
        sched_yield();

        if (rw_lock_trywrite(lock))
        {
            // If we must unqueue ourselves, remove
            if (w.flags & RW_WAITER_QUEUED)
            {
                // Note: We must re-check with the lock held since
                // it's the only condition where RW_WAITER_QUEUED changes.
                // If it's still set by the time we lock, we must dequeue ourselves.
                spin_lock(&lock->llock);
                if (!(w.flags & RW_WAITER_QUEUED))
                    spin_unlock(&lock->llock);
            }
            break;
        }
    }

    if (w.flags & RW_WAITER_QUEUED)
    {
        dequeue_thread_rwlock(lock, &w);
        spin_unlock(&lock->llock);
    }

    set_current_state(THREAD_RUNNABLE);

    return ret;
}

__always_inline int __rw_lock_write(rwlock *lock, int state)
{
    MAY_SLEEP();
    /* Try once before doing the whole preempt disable loop and all */
    if (!rw_lock_trywrite(lock) && !rw_lock_spin_write(lock)) [[unlikely]]
        return __rw_lock_write_slow(lock, state);
    return 0;
}

__noinline int __rw_lock_read_slow(rwlock *lock, int state)
{
    int ret = 0;
    thread *current = get_current_thread();
    const bool signals_allowed = state == THREAD_INTERRUPTIBLE;

    /**
     * Slow path algorithm:
     * First, lock the queue and queue ourselves in. Then, under the lock, try again. If we fail,
     * unlock and try to sleep. After we wake up, try again. *IF* we fail, restart.
     */
    rwlock_waiter w{current, 0};
    while (true)
    {
        spin_lock(&lock->llock);
        rwlock_prepare_sleep(lock, &w, state);

        if (rw_lock_tryread(lock) == 0)
            break;

        if (signals_allowed && signal_is_pending())
        {
            ret = -EINTR;
            break;
        }

        spin_unlock(&lock->llock);
        sched_yield();

        if (rw_lock_tryread(lock) == 0)
        {
            // If we must unqueue ourselves, remove
            if (w.flags & RW_WAITER_QUEUED)
            {
                // Note: We must re-check with the lock held since
                // it's the only condition where RW_WAITER_QUEUED changes.
                // If it's still set by the time we lock, we must dequeue ourselves.
                spin_lock(&lock->llock);
                if (!(w.flags & RW_WAITER_QUEUED))
                    spin_unlock(&lock->llock);
            }
            break;
        }
    }

    if (w.flags & RW_WAITER_QUEUED)
    {
        dequeue_thread_rwlock(lock, &w);
        spin_unlock(&lock->llock);
    }

    return ret;
}

__always_inline int __rw_lock_read(rwlock *lock, int state)
{
    MAY_SLEEP();
    /* Try once before doing the whole preempt disable loop and all */
    if (rw_lock_tryread(lock) < 0 && !rw_lock_spin_read(lock)) [[unlikely]]
        return __rw_lock_read_slow(lock, state);
    return 0;
}

void rw_lock_write(rwlock *lock)
{
    __rw_lock_write(lock, THREAD_UNINTERRUPTIBLE);
}

int rw_lock_write_interruptible(rwlock *lock)
{
    return __rw_lock_write(lock, THREAD_INTERRUPTIBLE);
}

void rw_lock_read(rwlock *lock)
{
    __rw_lock_read(lock, THREAD_UNINTERRUPTIBLE);
}

int rw_lock_read_interruptible(rwlock *lock)
{
    return __rw_lock_read(lock, THREAD_INTERRUPTIBLE);
}

void rwlock_wake(rwlock *lock)
{
    scoped_lock g{lock->llock};

    list_for_every_safe (&lock->waiting_list)
    {
        rwlock_waiter *w = container_of(l, rwlock_waiter, head);

        // We use read_once below to make sure that loads don't get re-ordered
        // or tear through dequeue_thread_rwlock, since at that point the other thread may be long
        // gone and we could be touching bad memory.
        auto flags = read_once(w->flags) & RW_WAITER_WRITER;
        auto thread = read_once(w->thr);
        dequeue_thread_rwlock(lock, w);
        thread_wake_up(thread);

        if (flags & RW_WAITER_WRITER)
            break;
    }

    if (list_is_empty(&lock->waiting_list))
        __atomic_and_fetch(&lock->lock, ~RDWR_LOCK_WAITERS, __ATOMIC_RELEASE);
}

void rw_unlock_read(rwlock *lock)
{
    /* Implementation note: If we're unlocking a read lock, only wake up a
     * single thread, since the write lock is exclusive, like a mutex.
     */
    if (__atomic_sub_fetch(&lock->lock, 1, __ATOMIC_RELEASE) & RDWR_LOCK_WAITERS)
        rwlock_wake(lock);
}

void rw_unlock_write(rwlock *lock)
{
    const bool has_waiters =
        __atomic_and_fetch(&lock->lock, RDWR_LOCK_WRITE_UNLOCK_MASK, __ATOMIC_RELEASE) &
        RDWR_LOCK_WAITERS;
    /* Implementation note: If we're unlocking a write lock, wake up every single thread
     * because we can have both readers and writers waiting to get woken up.
     */
    if (has_waiters)
        rwlock_wake(lock);
}

void rw_downgrade_write(struct rwlock *lock)
{
    const bool has_waiters =
        __atomic_exchange_n(&lock->lock, 1, __ATOMIC_RELEASE) & RDWR_LOCK_WAITERS;
    if (has_waiters)
        rwlock_wake(lock);
}

extern "C"
{

__always_inline bool rwslock_try_read_fast(struct rwslock *lock)
{
    unsigned long word = READ_ONCE(lock->lock);
    if (unlikely(word & RDWR_LOCK_WRITE || word == RDWR_MAX_COUNTER))
        return false;
    return __atomic_compare_exchange_n(&lock->lock, &word, word + 1, false, __ATOMIC_ACQUIRE,
                                       __ATOMIC_RELAXED);
}

__noinline static void __read_lock_slow(struct rwslock *lock)
{
    unsigned long l;
    unsigned long to_insert;

    l = READ_ONCE(lock->lock);
    do
    {
        while (l & RDWR_LOCK_WRITE || l == RDWR_MAX_COUNTER)
        {
            cpu_relax();
            l = READ_ONCE(lock->lock);
        }

        to_insert = l + 1;
    } while (!__atomic_compare_exchange_n(&lock->lock, &l, to_insert, false, __ATOMIC_ACQUIRE,
                                          __ATOMIC_RELAXED));
}

void __read_lock(struct rwslock *lock) NO_THREAD_SAFETY_ANALYSIS
{
    if (unlikely(!rwslock_try_read_fast(lock)))
        __read_lock_slow(lock);
}

void __read_unlock(struct rwslock *lock) RELEASE_SHARED(lock) NO_THREAD_SAFETY_ANALYSIS
{
    __atomic_sub_fetch(&lock->lock, 1, __ATOMIC_RELEASE);
}

__noinline static void __write_lock_slow(struct rwslock *lock)
{
    unsigned long expected = 0;
    const unsigned long write_value = RDWR_LOCK_WRITE | get_cpu_nr();

    expected = READ_ONCE(lock->lock);
    do
    {
        while (expected != 0)
        {
            cpu_relax();
            expected = READ_ONCE(lock->lock);
        }
    } while (!__atomic_compare_exchange_n(&lock->lock, &expected, write_value, false,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));
}

__always_inline bool rwslock_try_write_fast(struct rwslock *lock)
{
    unsigned long expected = 0;
    const unsigned long write_value = RDWR_LOCK_WRITE | get_cpu_nr();
    return __atomic_compare_exchange_n(&lock->lock, &expected, write_value, false, __ATOMIC_ACQUIRE,
                                       __ATOMIC_RELAXED);
}

void __write_lock(struct rwslock *lock) ACQUIRE(lock) NO_THREAD_SAFETY_ANALYSIS
{
    if (unlikely(!rwslock_try_write_fast(lock)))
        __write_lock_slow(lock);
}

void __write_unlock(struct rwslock *lock) RELEASE(lock) NO_THREAD_SAFETY_ANALYSIS
{
    __atomic_store_n(&lock->lock, 0, __ATOMIC_RELEASE);
}
}

int rwslock::try_read()
{
    sched_disable_preempt();
    unsigned long l;
    unsigned long to_insert;

    do
    {
        l = __atomic_load_n(&lock, __ATOMIC_RELAXED);
        if (l & RDWR_LOCK_WRITE || l == RDWR_MAX_COUNTER)
        {
            sched_enable_preempt();
            return -EAGAIN;
        }

        to_insert = l + 1;
    } while (!__atomic_compare_exchange_n(&lock, &l, to_insert, false, __ATOMIC_ACQUIRE,
                                          __ATOMIC_RELAXED));
    return 0;
}

int rwslock::try_write()
{
    sched_disable_preempt();
    unsigned long expected = 0;
    const unsigned long write_value = RDWR_LOCK_WRITE;
    if (!__atomic_compare_exchange_n(&lock, &expected, write_value, false, __ATOMIC_ACQUIRE,
                                     __ATOMIC_RELAXED))
    {
        sched_enable_preempt();
        return -EAGAIN;
    }

    return 0;
}

void rwslock::lock_read() NO_THREAD_SAFETY_ANALYSIS
{
    read_lock(this);
}

void rwslock::lock_write() NO_THREAD_SAFETY_ANALYSIS
{
    write_lock(this);
}

void rwslock::unlock_read() NO_THREAD_SAFETY_ANALYSIS
{
    read_unlock(this);
}

void rwslock::unlock_write() NO_THREAD_SAFETY_ANALYSIS
{
    write_unlock(this);
}

#ifdef CONFIG_KTEST_RWLOCK

#include <onyx/cpu.h>
#include <onyx/panic.h>

#include <libtest/libtest.h>

static volatile unsigned long counter = 0;
static rwlock rw_lock;
static unsigned int rw_alive_threads = 0;

static void rwlock_read(void *ctx)
{
    rw_alive_threads++;

    while (true)
    {
        rw_lock_read(&rw_lock);

        for (unsigned int i = 0; i < 0xffffff; i++)
        {
            unsigned long c0 = counter;

            for (unsigned int j = 0; j < 10; j++)
                cpu_relax();

            unsigned long c1 = counter;

            if (c1 != c0)
                panic("RwLock read lock broken");
        }

        unsigned long last_counter_read = counter;

        rw_unlock_read(&rw_lock);

        if (last_counter_read > 0x100000)
        {
            rw_alive_threads--;
            thread_exit();
        }
    }
}

void rwlock_write(void *__is_master)
{
    rw_alive_threads++;
    bool is_master = (bool) __is_master;

    while (true)
    {
        rw_lock_write(&rw_lock);

        for (unsigned int i = 0; i < 0xffffff; i++)
        {
            unsigned long c0 = counter;
            counter = counter + 1;

            for (unsigned int j = 0; j < 10; j++)
                cpu_relax();

            unsigned long c1 = counter;

            if (c1 != c0 + 1)
                panic("RwLock write lock broken");
        }

        unsigned long last_counter_read = counter;

        rw_unlock_write(&rw_lock);

        if (last_counter_read > 0x100000)
        {
            rw_alive_threads--;
            if (!is_master)
                thread_exit();
            else
                return;
        }
    }
}

bool rwlock_test(void)
{
    rw_alive_threads = 0;
    rwlock_init(&rw_lock);

    counter = 0;

    /* This test runs using 2 reading threads and two writing threads, constantly
     * hammering a counter variable and checking if it changed while the lock is being held.
     */

    struct thread *write2 = sched_create_thread(rwlock_write, THREAD_KERNEL, NULL);
    assert(write2 != NULL);
    sched_start_thread(write2);

    struct thread *read1 = sched_create_thread(rwlock_read, THREAD_KERNEL, NULL);
    assert(read1 != NULL);
    struct thread *read2 = sched_create_thread(rwlock_read, THREAD_KERNEL, NULL);
    assert(read2 != NULL);
    sched_start_thread(read1);
    sched_start_thread(read2);

    rwlock_write((void *) 1);

    while (rw_alive_threads != 0)
        cpu_relax();

    return true;
}

DECLARE_TEST(rwlock_test, 4);

#endif
