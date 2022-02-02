/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_PIPE_H
#define _KERNEL_PIPE_H

#include <onyx/vfs.h>

#ifdef __cplusplus

#include <onyx/mutex.h>
#include <onyx/refcount.h>
#include <onyx/wait_queue.h>

#include <onyx/atomic.hpp>

constexpr unsigned long default_pipe_size = UINT16_MAX;

class pipe : public refcountable
{
private:
    void *buffer;
    size_t buf_size;
    size_t pos;
    struct spinlock pipe_lock;

    wait_queue write_queue;
    wait_queue read_queue;

    unsigned int eof : 1, broken : 1;

    bool can_read() const
    {
        return pos != 0;
    }

    bool can_read_or_eof() const
    {
        return can_read() || eof;
    }

    bool can_write() const
    {
        return pos < buf_size;
    }

    bool can_write_or_broken() const
    {
        return pos < buf_size || broken;
    }

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
    short poll(void *poll_file, short events);

    void wake_all(wait_queue *wq)
    {
        wait_queue_wake_all(wq);
    }
};

extern "C"
#endif

    int
    pipe_create(struct file **pipe_readable, struct file **pipe_writeable);

#endif
