/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_RWLOCK_H
#define _ONYX_RWLOCK_H

#include <onyx/compiler.h>
#include <onyx/limits.h>
#include <onyx/list.h>
#include <onyx/lock_annotations.h>
#include <onyx/spinlock.h>

#define ULONG_WIDTH (sizeof(unsigned long) * CHAR_BIT)

#define RDWR_LOCK_WAITERS      (1UL << (ULONG_WIDTH - 2))
#define RDWR_LOCK_WRITE        (1UL << (ULONG_WIDTH - 1))
#define RDWR_LOCK_COUNTER_MASK ((1UL << (ULONG_WIDTH - 2)) - 1)

#define RDWR_LOCK_WRITE_UNLOCK_MASK (~(RDWR_LOCK_WRITE | RDWR_LOCK_COUNTER_MASK))
#define RDWR_MAX_COUNTER            RDWR_LOCK_COUNTER_MASK

/**
 * rwlock counter:
 * bit N (64 or 32 probably) ..................... bit 0
 * | Write | Waiters | "Counter" |
 * Meaning of the bits:
 * Write - is write locked
 * Waiters - has waiters (if sleepable locked, these waiters are queued)
 * Counter - If write locked, this holds the owner of the lock. Else, 0 OR
 *           the read counter.
 * Worth noting that the "owner" of the lock is a thread * shifted down, so
 * the lower bits (currently 2, may change) must be 0.
 */

struct rwlock
{
    unsigned long lock;
    struct list_head waiting_list;
    struct spinlock llock;

#ifdef __cplusplus
    constexpr rwlock() : lock{0}
    {
        spinlock_init(&llock);
        INIT_LIST_HEAD(&waiting_list);
    }
#endif
};

int rw_lock_tryread(struct rwlock *lock);
void rw_lock_read(struct rwlock *lock);
void rw_lock_write(struct rwlock *lock);
int rw_lock_write_interruptible(struct rwlock *lock);
int rw_lock_read_interruptible(struct rwlock *lock);
void rw_unlock_read(struct rwlock *lock);
void rw_unlock_write(struct rwlock *lock);

static inline void rwlock_init(struct rwlock *lock)
{
    lock->lock = 0;
    INIT_LIST_HEAD(&lock->waiting_list);
    spinlock_init(&lock->llock);
}

#ifdef __cplusplus

struct CAPABILITY("rwslock") rwslock
{
private:
    unsigned long lock{0};

public:
    constexpr rwslock() = default;

    void lock_read() ACQUIRE_SHARED(this);
    void lock_write() ACQUIRE(this);

    void unlock_read() RELEASE_SHARED(this);
    void unlock_write() RELEASE(this);

    int try_read() TRY_ACQUIRE_SHARED(0, this);
    int try_write() TRY_ACQUIRE(0, this);
};

#define RWSLOCK rwslock

enum class rw_lock
{
    read = 0,
    write
};

template <rw_lock lock_type>
class scoped_rwlock
{
private:
    bool IsLocked;
    rwlock &internal_lock;

public:
    constexpr bool read() const
    {
        return lock_type == rw_lock::read;
    }

    constexpr bool write() const
    {
        return lock_type == rw_lock::write;
    }

    void lock()
    {
        if (read())
            rw_lock_read(&internal_lock);
        else
            rw_lock_write(&internal_lock);
        IsLocked = true;
    }

    void unlock()
    {
        if (read())
            rw_unlock_read(&internal_lock);
        else
            rw_unlock_write(&internal_lock);
        IsLocked = false;
    }

    scoped_rwlock(rwlock &lock) : internal_lock(lock)
    {
        this->lock();
    }

    scoped_rwlock(rwlock &lock, bool autolock) : internal_lock(lock)
    {
        if (autolock)
            this->lock();
    }

    ~scoped_rwlock()
    {
        if (IsLocked)
            unlock();
    }
};

template <rw_lock lock_type>
class SCOPED_CAPABILITY scoped_rwslock
{
private:
    bool IsLocked;
    rwslock &internal_lock;

public:
    constexpr bool read() const
    {
        return lock_type == rw_lock::read;
    }

    constexpr bool write() const
    {
        return lock_type == rw_lock::write;
    }

    void lock() ACQUIRE()
    {
        if (read())
            internal_lock.lock_read();
        else
            internal_lock.lock_write();
        IsLocked = true;
    }

    void unlock() RELEASE()
    {
        if (read())
            internal_lock.unlock_read();
        else
            internal_lock.unlock_write();
        IsLocked = false;
    }

    scoped_rwslock(rwslock &lock) ACQUIRE(lock) : internal_lock(lock)
    {
        this->lock();
    }

    scoped_rwslock(rwslock &lock, bool autolock) ACQUIRE(lock) : internal_lock(lock)
    {
        if (autolock)
            this->lock();
    }

    ~scoped_rwslock() RELEASE()
    {
        if (IsLocked)
            unlock();
    }
};

#else
#define RWSLOCK unsigned long
#endif

#endif
