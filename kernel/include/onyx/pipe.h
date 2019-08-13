/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PIPE_H
#define _KERNEL_PIPE_H

#include <onyx/vfs.h>

#ifdef __cplusplus

#include <onyx/refcount.h>
#include <onyx/atomic.hpp>
#include <onyx/condvar.h>
#include <onyx/mutex.h>

constexpr unsigned long default_pipe_size = UINT16_MAX;

class pipe : public refcountable
{
private:
	void *buffer;
	size_t buf_size;
	size_t pos;
	struct mutex pipe_lock;
	/* Is signaled when space is available in the buffer */
	struct cond write_cond;
	/* Is signaled when the buffer has data in it */
	struct cond read_cond;
public:
	atomic<size_t> reader_count;
	atomic<size_t> writer_count;
	constexpr pipe();
	~pipe();
	bool allocate_pipe_buffer(unsigned long buffer_size = default_pipe_size);
	ssize_t read(int flags, size_t len, void *buffer);
	ssize_t write(int flags, size_t len, const void *buffer);
	bool is_full() const;
	size_t available_space() const;
	void close_read_end();
	void close_write_end();
};

extern "C"
#endif

int pipe_create(struct inode **pipe_readable, struct inode **pipe_writeable);



#endif
