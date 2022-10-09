/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_RWLOCK_H
#define _KERNEL_RWLOCK_H

#include <onyx/compiler.h>
#include <onyx/limits.h>
#include <onyx/list.h>
#include <onyx/spinlock.h>

#define RDWR_LOCK_WRITE LONG_MAX

struct rwlock
{
    unsigned long lock;
    struct list_head waiting_list;
    struct spinlock llock;

#ifdef __cplusplus
    constexpr rwlock() : lock{}, waiting_list{}, llock{}
    {
        spinlock_init(&llock);
        INIT_LIST_HEAD(&waiting_list);
    }
#endif
};

struct rwslock
{
private:
    unsigned long lock{0};

public:
    constexpr rwslock() = default;

    void lock_read();
    void lock_write();

    void unlock_read();
    void unlock_write();

    int try_read();
    int try_write();
};

bool rw_lock_tryread(struct rwlock *lock);
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
class scoped_rwslock
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

    void lock()
    {
        if (read())
            internal_lock.lock_read();
        else
            internal_lock.lock_write();
        IsLocked = true;
    }

    void unlock()
    {
        if (read())
            internal_lock.unlock_read();
        else
            internal_lock.unlock_write();
        IsLocked = false;
    }

    scoped_rwslock(rwslock &lock) : internal_lock(lock)
    {
        this->lock();
    }

    scoped_rwslock(rwslock &lock, bool autolock) : internal_lock(lock)
    {
        if (autolock)
            this->lock();
    }

    ~scoped_rwslock()
    {
        if (IsLocked)
            unlock();
    }
};

#endif

#endif
