/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_HYBRID_LOCK_H
#define _ONYX_HYBRID_LOCK_H

#include <onyx/spinlock.h>
#include <onyx/wait_queue.h>

__BEGIN_CDECLS

struct socket;
void sock_do_post_work(struct socket *sock);
bool sock_needs_work(struct socket *sock);
/**
 * @brief Works in a similar fashion to linux's socket_lock_t.
 * When used in a user context, the lock's user is supposed to lock it like a mutex, which may
 * block. When used in a bottom-half-like context, the user is supposed to take the lock, and check
 * if it actually owns it.
 *
 */
struct hybrid_lock
{
    struct spinlock lock_;
    raw_spinlock_t owned;
    struct wait_queue wq;

#ifdef __cplusplus
    void __wait_for_owned()
    {
        wait_for_event_locked(&wq, owned == 0, &lock_);
    }

    void lock()
    {
        scoped_lock g{lock_};

        if (owned)
            __wait_for_owned();
        owned = get_cpu_nr() + 1;
    }

    void unlock_sock(socket *sock)
    {
        scoped_lock g{lock_};

        if (sock_needs_work(sock)) [[unlikely]]
            sock_do_post_work(sock);

        owned = 0;
        wait_queue_wake(&wq);
    }

    void unlock()
    {
        scoped_lock g{lock_};
        owned = 0;
        wait_queue_wake(&wq);
    }

    void lock_bh()
    {
        spin_lock(&lock_);
    }

    void unlock_bh()
    {
        spin_unlock(&lock_);
    }

    bool is_ours() const
    {
        return owned == 0;
    }
#endif
};

static inline void hybrid_lock_init(struct hybrid_lock *lock)
{
    init_wait_queue_head(&lock->wq);
    spinlock_init(&lock->lock_);
    lock->owned = 0;
}

static inline void sk_wait_for_owned(struct hybrid_lock *lock)
{
    wait_for_event_locked(&lock->wq, lock->owned == 0, &lock->lock_);
}

static inline void hybrid_lock(struct hybrid_lock *lock)
{
    spin_lock(&lock->lock_);
    if (lock->owned)
        sk_wait_for_owned(lock);
    lock->owned = get_cpu_nr() + 1;
    spin_unlock(&lock->lock_);
}

static inline void __unlock_sock(struct hybrid_lock *lock, struct socket *sock)
{
    spin_lock(&lock->lock_);

    if (unlikely(sock_needs_work(sock)))
        sock_do_post_work(sock);

    lock->owned = 0;

    wait_queue_wake(&lock->wq);
    spin_unlock(&lock->lock_);
}

static inline void hybrid_lock_bh(struct hybrid_lock *lock)
{
    spin_lock(&lock->lock_);
}

static inline void hybrid_unlock_bh(struct hybrid_lock *lock)
{
    spin_unlock(&lock->lock_);
}

static inline bool hybrid_is_ours(const struct hybrid_lock *lock)
{
    return READ_ONCE(lock->owned) == 0;
}

__END_CDECLS

#ifdef __cplusplus

#include <onyx/scoped_lock.h>

template <bool bh = false>
class scoped_hybrid_lock
{
private:
    bool IsLocked;
    struct hybrid_lock &lock_;
    socket *sock;

public:
    void lock()
    {
        if (bh)
            lock_.lock_bh();
        else
            lock_.lock();
        IsLocked = true;
    }

    void unlock()
    {
        if (bh)
            lock_.unlock_bh();
        else
            lock_.unlock_sock(sock);
        IsLocked = false;
    }

    explicit scoped_hybrid_lock(struct hybrid_lock &lock, socket *sock) : lock_{lock}, sock{sock}
    {
        this->lock();
    }

    ~scoped_hybrid_lock()
    {
        if (IsLocked)
            unlock();
    }
};
#endif

#endif
