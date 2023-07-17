/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_SCOPED_LOCK_H
#define _ONYX_SCOPED_LOCK_H

#include <onyx/enable_if.h>
#include <onyx/lock_annotations.h>
#include <onyx/mutex.h>
#include <onyx/spinlock.h>

template <typename LockType, bool irq_save = false>
class scoped_lock
{
private:
    bool IsLocked;
    LockType& internal_lock;

public:
    void lock() ACQUIRE(internal_lock)
    {
        if (irq_save)
            internal_lock.LockIrqsave();
        else
            internal_lock.Lock();
        IsLocked = true;
    }

    void unlock() RELEASE(internal_lock)
    {
        if (irq_save)
            internal_lock.UnlockIrqrestore();
        else
            internal_lock.Unlock();
        IsLocked = false;
    }

    scoped_lock(LockType& lock) : internal_lock(lock)
    {
        this->lock();
    }

    ~scoped_lock()
    {
        if (IsLocked)
            unlock();
    }
};

template <bool irq_save>
class scoped_lock<spinlock, irq_save>
{
private:
    bool is_locked;
    spinlock& internal_lock;
    unsigned long cpu_flags; /* TODO: Optimise this out from non-irqsave locks */
public:
    void lock()
    {
        if constexpr (irq_save)
            cpu_flags = spin_lock_irqsave(&internal_lock);
        else
            spin_lock(&internal_lock);
        is_locked = true;
    }

    void unlock()
    {
        if constexpr (irq_save)
            spin_unlock_irqrestore(&internal_lock, cpu_flags);
        else
            spin_unlock(&internal_lock);
        is_locked = false;
    }

    scoped_lock(spinlock& lock) : internal_lock(lock), cpu_flags{}
    {
        this->lock();
    }

    ~scoped_lock()
    {
        if (is_locked)
            unlock();
    }

    scoped_lock(const scoped_lock& l) = delete;
    scoped_lock& operator=(const scoped_lock& rhs) = delete;

    constexpr scoped_lock(scoped_lock&& l) : is_locked{l.is_locked}, internal_lock{l.internal_lock}
    {
        l.is_locked = false;
    }

    constexpr scoped_lock& operator=(scoped_lock&& rhs)
    {
        internal_lock = rhs.internal_lock;
        is_locked = rhs.is_locked;
        rhs.is_locked = false;

        return *this;
    }

    void keep_locked()
    {
        is_locked = false;
    }
};

template <bool interruptible = false>
class SCOPED_CAPABILITY scoped_mutex
{
private:
    mutex& internal_lock;
    bool is_locked;

public:
    void lock() ACQUIRE()
    {
        if constexpr (interruptible)
        {
            /* if we've failed to lock the mutex, we got -EINTR, so we don't set is_locked */
            if (mutex_lock_interruptible(&internal_lock) < 0)
                return;
        }
        else
            mutex_lock(&internal_lock);
        is_locked = true;
    }

    void unlock() RELEASE()
    {
        mutex_unlock(&internal_lock);
        is_locked = false;
    }

    explicit scoped_mutex(mutex& lock) ACQUIRE(lock) : internal_lock(lock), is_locked{false}
    {
        this->lock();
    }

    explicit scoped_mutex(mutex& lock, bool should_auto_lock) ACQUIRE(lock)
        : internal_lock(lock), is_locked{false}
    {
        if (should_auto_lock)
            this->lock();
    }

    ~scoped_mutex() RELEASE()
    {
        if (is_locked) [[likely]]
            unlock();
    }

    scoped_mutex(const scoped_mutex& l) = delete;
    scoped_mutex& operator=(const scoped_mutex& rhs) = delete;

    scoped_mutex(scoped_mutex&& l)
    {
        internal_lock = l.internal_lock;
        is_locked = l.is_locked;
        l.is_locked = false;
        l.internal_lock = nullptr;
    }

    scoped_mutex& operator=(scoped_mutex&& rhs)
    {
        internal_lock = rhs.internal_lock;
        is_locked = rhs.is_locked;
        rhs.is_locked = false;
        rhs.internal_lock = nullptr;

        return *this;
    }

    void keep_locked()
    {
        is_locked = false;
    }

    bool locked() const
    {
        return is_locked;
    }
};

class Spinlock;

#endif
