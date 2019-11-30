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

class poll_file
{
private:
	struct inode *file;
	short events;
	short revents;
	struct wait_queue_token wait_token;
	struct wait_queue *queue;
public:
	constexpr poll_file(struct inode *f, short events) : file{f},
		events{events}, revents{0}, wait_token{}, queue{} {}
	
	/* To keep vector happy */
	constexpr poll_file() : file{}, events{}, revents{}, wait_token{}, queue{} {}

	void stop_wait_on();
	
	~poll_file()
	{
		stop_wait_on();
		/* Unreference the file */
		if(file)
			close_vfs(file);
	}

	/* Delete copy contructors */
	poll_file& operator=(poll_file& rhs) = delete;
	poll_file(poll_file& rhs) = delete;

	/* Implement move constructors for cul::vector<> */
	poll_file& operator=(poll_file&& rhs)
	{
		this->events = rhs.events;
		this->revents = rhs.revents;
		this->file = rhs.file;
		this->wait_token = rhs.wait_token;
		this->queue = rhs.queue;

		rhs.queue = nullptr;
		rhs.wait_token.thread = nullptr;
		rhs.file = nullptr;

		return *this;
	}

	poll_file(poll_file&& rhs)
	{
		this->events = rhs.events;
		this->revents = rhs.revents;
		this->file = rhs.file;
		this->wait_token = rhs.wait_token;
		this->queue = rhs.queue;

		rhs.queue = nullptr;
		rhs.wait_token.thread = nullptr;
		rhs.file = nullptr;
	}

	void set_wait_queue(wait_queue *q)
	{
		queue = q;
	}

	/* Note: Doesn't block, just queues it on the wait queue */
	void wait_on();
};

class poll_table
{
private:
	struct spinlock poll_table_lock;
	cul::vector<poll_file> poll_table_array;
	
	/* After adding every file to the array, we set this to false in order
	 * to avoid requeuing everything again. Therefore, once queued always queued until we remove it */
	bool is_queueing;
public:
	constexpr poll_table() : poll_table_lock{}, poll_table_array{}, is_queueing{true} {}
	~poll_table() {}

	void wait(struct inode *ino, short events, wait_queue *queue);
};

#endif

#endif