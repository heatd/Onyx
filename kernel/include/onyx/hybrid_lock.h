/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_HYBRID_LOCK_H
#define _ONYX_HYBRID_LOCK_H

#include <onyx/wait_queue.h>
#include <onyx/spinlock.h>
#include <onyx/conditional.h>
#include <onyx/scoped_lock.h>

struct socket;
void sock_do_post_work(socket *sock);
bool sock_needs_work(socket *sock);
/**
 * @brief Works in a similar fashion to linux's socket_lock_t.
 * When used in a user context, the lock's user is supposed to lock it like a mutex, which may block.
 * When used in a bottom-half-like context, the user is supposed to take the lock, and check if it
 * actually owns it.
 * 
 */
class hybrid_lock
{
private:
	spinlock lock_;
	raw_spinlock_t owned;
	wait_queue wq;

	void __wait_for_owned()
	{
		wait_for_event_locked(&wq, owned != 0, &lock_);
	}

public:

	hybrid_lock() : owned{}, wq{}
	{
		init_wait_queue_head(&wq);
		spinlock_init(&lock_);
	}

	void lock()
	{
		scoped_lock g{lock_};

		if(owned)
			__wait_for_owned();
		owned = get_cpu_nr() + 1;
	}

	void unlock_sock(socket *sock)
	{
		scoped_lock g{lock_};

		if(sock_needs_work(sock)) [[unlikely]]
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
};

template <bool bh = false>
class scoped_hybrid_lock
{
private:
	bool IsLocked;
	hybrid_lock& lock_;
	socket *sock;
public:
	void lock()
	{
		if(bh)
			lock_.lock_bh();
		else
			lock_.lock();
		IsLocked = true;
	}

	void unlock()
	{
		if(bh)
			lock_.unlock_bh();
		else
			lock_.unlock_sock(sock);
		IsLocked = false;
	}

	explicit scoped_hybrid_lock(hybrid_lock& lock, socket *sock) : lock_{lock}, sock{sock}
	{
		this->lock();
	}

	~scoped_hybrid_lock()
	{
		if(IsLocked)
			unlock();
	}
};

#endif
