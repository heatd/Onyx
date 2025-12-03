/*
 * Copyright (c) 2017 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_RWLOCK_H
#define _ONYX_RWLOCK_H

#include <onyx/compiler.h>
#include <onyx/limits.h>
#include <onyx/list.h>
#include <onyx/lock_annotations.h>
#include <onyx/spinlock.h>

#include <linux/lockdep_types.h>

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
#ifdef CONFIG_LOCKDEP
    struct lockdep_map dep_map;
#endif
#ifdef __cplusplus
    rwlock() = delete;
    rwlock(int)
    {
#ifdef CONFIG_LOCKDEP
        dep_map.name = "placeholder_rwlock";
        dep_map.wait_type_inner = LD_WAIT_SLEEP;
#endif
    }
#define LOCKDEP_OK {0}
#else
#define LOCKDEP_OK
#endif
};

#ifdef CONFIG_LOCKDEP
#define RWLOCK_LOCKDEP_INIT(lockname)       \
    , .dep_map = {                          \
          .name = #lockname,                \
          .wait_type_inner = LD_WAIT_SLEEP, \
    }
#else
#define RWLOCK_LOCKDEP_INIT(lockname)
#endif

#define RWLOCK_INITIALIZER(name)                \
    {.llock = __SPIN_LOCK_UNLOCKED(name.llock), \
     .waiting_list = LIST_HEAD_INIT(name.waiting_list) RWLOCK_LOCKDEP_INIT(name)}

#ifdef __cplusplus
#define DEFINE_RWLOCK(name) struct rwlock name LOCKDEP_OK
#else
#define DEFINE_RWLOCK(name) struct rwlock name = RWLOCK_INITIALIZER(name)
#endif

__BEGIN_CDECLS

int rw_lock_tryread(struct rwlock *lock);
void rw_lock_read(struct rwlock *lock);
void rw_lock_write(struct rwlock *lock);
void rw_lock_read_nested(struct rwlock *lock, unsigned int subclass);
void rw_lock_write_nested(struct rwlock *lock, unsigned int subclass);
int rw_lock_write_interruptible(struct rwlock *lock);
int rw_lock_read_interruptible(struct rwlock *lock);
void rw_unlock_read(struct rwlock *lock);
void rw_unlock_write(struct rwlock *lock);
void rw_downgrade_write(struct rwlock *lock);

#ifndef __IS_LINUX
static inline void __rwlock_init(struct rwlock *lock)
{
    lock->lock = 0;
    INIT_LIST_HEAD(&lock->waiting_list);
    spinlock_init(&lock->llock);
}

#ifdef CONFIG_LOCKDEP
void rwlock_init_lock_map(struct rwlock *lock, const char *name, struct lock_class_key *key);
#define rwlock_init(lock)                          \
    do                                             \
    {                                              \
        static struct lock_class_key __key;        \
                                                   \
        __rwlock_init((lock));                     \
        rwlock_init_lock_map(lock, #lock, &__key); \
    } while (0)
#else
#define rwlock_init(lock) __rwlock_init(lock)
#endif

__END_CDECLS

typedef struct CAPABILITY("rwslock") rwslock
{
    unsigned long lock;

#ifdef __cplusplus
    constexpr rwslock()
    {
        lock = 0;
    }

    void lock_read() ACQUIRE_SHARED(this);
    void lock_write() ACQUIRE(this);

    void unlock_read() RELEASE_SHARED(this);
    void unlock_write() RELEASE(this);

    int try_read() TRY_ACQUIRE_SHARED(0, this);
    int try_write() TRY_ACQUIRE(0, this);
#endif
} rwslock_t;

CONSTEXPR static inline void rwslock_init(struct rwslock *rwl)
{
    rwl->lock = 0;
}

__BEGIN_CDECLS

void __read_lock(struct rwslock *lock) ACQUIRE_SHARED(lock);
void __read_unlock(struct rwslock *lock) RELEASE_SHARED(lock);
void __write_lock(struct rwslock *lock) ACQUIRE(lock);
void __write_unlock(struct rwslock *lock) RELEASE(lock);

static inline void read_lock(struct rwslock *lock) ACQUIRE_SHARED(lock)
{
    sched_disable_preempt();
    __read_lock(lock);
}

static inline void read_unlock(struct rwslock *lock) RELEASE_SHARED(lock)
{
    __read_unlock(lock);
    sched_enable_preempt();
}

static inline void write_lock(struct rwslock *lock) ACQUIRE(lock)
{
    sched_disable_preempt();
    __write_lock(lock);
}

static inline void write_unlock(struct rwslock *lock) RELEASE(lock)
{
    __write_unlock(lock);
    sched_enable_preempt();
}

__END_CDECLS

#ifdef __cplusplus

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

    void lock(unsigned int subclass = 0)
    {
        if (read())
            rw_lock_read_nested(&internal_lock, subclass);
        else
            rw_lock_write_nested(&internal_lock, subclass);
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

    scoped_rwlock(rwlock &lock, unsigned int subclass = 0) : internal_lock(lock)
    {
        this->lock(subclass);
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
#define RWSLOCK struct rwslock
#endif

#endif
