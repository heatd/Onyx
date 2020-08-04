/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_POLL_H
#define _ONYX_POLL_H

#include <poll.h>

#include <onyx/vfs.h>

#ifdef __cplusplus

#include <onyx/vector.h>
#include <onyx/spinlock.h>
#include <onyx/wait_queue.h>
#include <onyx/memory.hpp>
#include <onyx/file.h>
#include <onyx/signal.h>

class poll_file;

class poll_file_entry
{
private:
	poll_file *f;
	struct wait_queue_token wait_token;
	struct wait_queue *queue;
public:
	constexpr poll_file_entry(poll_file *f, struct wait_queue *q) : f{f}, wait_token{}, queue{q} {}
	
	/* To keep vector happy */
	constexpr poll_file_entry() : f{nullptr}, wait_token{}, queue{} {}

	void stop_wait_on();
	
	~poll_file_entry()
	{
		stop_wait_on();
	}

	/* Delete copy contructors */
	poll_file_entry& operator=(const poll_file_entry& rhs) = delete;
	poll_file_entry(const poll_file_entry& rhs) = delete;

	/* Implement move constructors for cul::vector<> */
	poll_file_entry& operator=(poll_file_entry&& rhs)
	{
		this->wait_token = rhs.wait_token;
		this->queue = rhs.queue;
		this->f = rhs.f;

		rhs.f = nullptr;
		rhs.queue = nullptr;
		rhs.wait_token.thread = nullptr;

		return *this;
	}

	poll_file_entry(poll_file_entry&& rhs)
	{
		this->wait_token = rhs.wait_token;
		this->queue = rhs.queue;

		rhs.queue = nullptr;
		rhs.wait_token.thread = nullptr;
	}

	void set_wait_queue(wait_queue *q)
	{
		queue = q;
	}

	/* Note: Doesn't block, just queues it on the wait queue */
	void wait_on();
	static void wake_callback(void *context, struct wait_queue_token *tkn);
};

class poll_table;

class poll_file
{
private:
	poll_table* pt;
	cul::vector<unique_ptr<poll_file_entry> > entries;
	struct file *file;
	short events;
	short revents;
	struct pollfd *upoll;
	int fd;
public:
	
	constexpr poll_file(int fd, poll_table* pt, struct file *f, short events, struct pollfd *__u) :
			pt{pt}, entries{}, file{f}, events{events},
			revents{0}, upoll(__u), fd{fd}
	{
		/* Get a reference to the file! */
		fd_get(f);
	}

	constexpr poll_file() : pt{}, entries{}, file{}, events{}, revents{}, upoll{nullptr}, fd{-1} {}

	~poll_file()
	{
		if(file)
			fd_put(file);
	}

	/* Delete copy contructors */
	poll_file& operator=(const poll_file& rhs) = delete;
	poll_file(const poll_file& rhs) = delete;

	poll_file& operator=(poll_file&& rhs)
	{
		this->entries = cul::move(rhs.entries);
		this->events = rhs.events;
		this->file = rhs.file;
		this->revents = rhs.events;
		this->pt = rhs.pt;
		this->upoll = rhs.upoll;
		this->fd = rhs.fd;
	
		rhs.entries = {};
		rhs.events = 0;
		rhs.file = 0;
		rhs.revents = 0;
		rhs.pt = nullptr;
		rhs.fd = 0;

		return *this;
	}

	poll_file(poll_file&& rhs)
	{
		this->entries = cul::move(rhs.entries);
		this->events = rhs.events;
		this->file = rhs.file;
		this->revents = rhs.events;
		this->pt = rhs.pt;
		this->upoll = rhs.upoll;
		this->fd = rhs.fd;
	
		rhs.entries = {};
		rhs.events = 0;
		rhs.file = 0;
		rhs.revents = 0;
		rhs.pt = nullptr;
		rhs.fd = 0;
	}

	void wait(wait_queue *queue);

	struct file *get_file() const
	{
		return file;
	}

	struct pollfd *get_upollfd() const
	{
		return upoll;
	}

	short get_event_mask() const
	{
		return events;
	}

	short get_efective_event_mask() const
	{
		/* POLLHUP and POLLERR are implicit */
		return events | (POLLHUP | POLLERR);
	}

	int get_fd() const
	{
		return fd;
	}

	void signal();
};

enum class sleep_result
{
	signal = 0,
	woken_up = 1,
	timeout = 2
};

class poll_table
{
private:
	cul::vector<poll_file> poll_table_array;
	bool signaled;
	
	/* After adding every file to the array, we set this to false in order
	 * to avoid requeuing everything again. Therefore, once queued always queued until we remove it */
	bool is_queueing;
public:
	constexpr poll_table() : poll_table_array{}, signaled{false}, is_queueing{true} {}
	~poll_table() {}

	cul::vector<poll_file>& get_poll_table()
	{
		return poll_table_array;
	}

	void signal()
	{
		signaled = true;
	}

	bool may_queue() const
	{
		return is_queueing;
	}

	void dont_queue()
	{
		is_queueing = false;
	}

	bool was_signaled() const
	{
		return signaled;
	}
	
	/* timeout in ms - negative means infinite, 0 means don't sleep */
	sleep_result sleep_poll(hrtime_t timeout, bool timeout_valid) const;
};

extern "C"
{
#endif

void poll_wait_helper(void *poll_file, struct wait_queue *q);

struct pselect_arg
{
	const sigset_t *mask;
	size_t length;
};

int sys_pselect(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, const struct timespec *timeout,
                struct pselect_arg *arg);

#ifdef __cplusplus
}
#endif

#endif
