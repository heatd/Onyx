/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/limits.h>
#include <onyx/panic.h>
#include <onyx/pipe.h>
#include <onyx/poll.h>
#include <onyx/process.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>
#include <onyx/utils.h>

#include <onyx/list.hpp>

static chardev *pipedev = nullptr;
static atomic<ino_t> current_inode_number = 0;

pipe::pipe()
    : refcountable(2), buffer(nullptr), buf_size(0),
      pos(0), eof{}, broken{}, reader_count{1}, writer_count{1}
{
    init_wait_queue_head(&write_queue);
    init_wait_queue_head(&read_queue);
}

pipe::~pipe()
{
    free((void *) buffer);
}

bool pipe::allocate_pipe_buffer(unsigned long buf_size)
{
    buffer = zalloc(buf_size);
    if (buffer)
    {
        this->buf_size = buf_size;
        return true;
    }

    return false;
}

bool pipe::is_full() const
{
    return buf_size == pos;
}

size_t pipe::available_space() const
{
    return buf_size - pos;
}

ssize_t pipe::read(int flags, size_t len, void *buf)
{
    ssize_t been_read = 0;

    scoped_mutex g{pipe_lock};

    while (been_read != (ssize_t) len)
    {
        if (can_read())
        {
            size_t to_read = min(len - been_read, pos);
            if (copy_to_user((void *) ((char *) buf + been_read), buffer, to_read) < 0)
            {

                /* Note: We do need to signal writers and readers on EFAULT if we have read/written
                 */
                if (been_read != 0)
                    wake_all(&write_queue);

                return -EFAULT;
            }

            /* move the rest of the buffer back to the beginning if we have to */
            if (pos - to_read != 0)
                memmove(buffer, (const void *) ((char *) buffer + to_read), pos - to_read);

            pos -= to_read;
            been_read += to_read;
            wake_all(&write_queue);
        }
        else
        {
            if (been_read || eof)
                return been_read;

            /* buffer empty */
            if (flags & O_NONBLOCK)
            {
                return -EAGAIN;
            }

            if (wait_for_event_mutex_interruptible(&read_queue, can_read_or_eof(), &pipe_lock) ==
                -EINTR)
                return -EINTR;
        }
    }

    return been_read;
}

ssize_t pipe::write(int flags, size_t len, const void *buf)
{
    bool is_atomic_write = len <= PIPE_BUF;
    ssize_t written = 0;

    scoped_mutex g{pipe_lock};

    while (written != (ssize_t) len)
    {
        if (broken)
        {
            kernel_raise_signal(SIGPIPE, get_current_process(), 0, nullptr);
            return -EPIPE;
        }

        if (((available_space() < (len - written)) && is_atomic_write) || is_full())
        {
            if (written != 0)
            {
                /* now that we're blocking, might as well signal readers */
                wake_all(&read_queue);
            }

            if (flags & O_NONBLOCK)
            {
                return -EAGAIN;
            }

            if (wait_for_event_mutex_interruptible(
                    &write_queue,
                    (is_atomic_write && available_space() >= (len - written)) || !is_full() ||
                        broken,
                    &pipe_lock) == -EINTR)
                return -EINTR;
        }
        else
        {
            size_t to_write = min(len - written, available_space());
            /* sigh - sometimes C++ really gets in the way */
            if (copy_from_user((void *) ((char *) buffer + pos),
                               (const void *) ((char *) buf + written), to_write) < 0)
            {
                /* Note: We do need to signal writers and readers on EFAULT if we have read/written
                 */
                if (written != 0)
                    wake_all(&read_queue);
                return -EFAULT;
            }

            pos += to_write;
            written += to_write;
        }
    }

    /* After finishing the write, signal any possible readers */
    wake_all(&read_queue);

    return written;
}

#define PIPE_WRITEABLE 0x1

pipe *get_pipe(void *helper)
{
    unsigned long raw = (unsigned long) helper;

    return (pipe *) ((void *) (raw & ~PIPE_WRITEABLE));
}

size_t pipe_read(size_t offset, size_t sizeofread, void *buffer, struct file *file)
{
    (void) offset;
    pipe *p = get_pipe(file->f_ino->i_helper);
    return p->read(file->f_flags, sizeofread, buffer);
}

size_t pipe_write(size_t offset, size_t sizeofwrite, void *buffer, struct file *file)
{
    (void) offset;
    pipe *p = get_pipe(file->f_ino->i_helper);
    return p->write(file->f_flags, sizeofwrite, buffer);
}

void pipe::close_write_end()
{
    /* wake up any possibly-blocked writers */
    scoped_mutex g{pipe_lock};

    if (--writer_count == 0)
    {
        eof = 1;
        wake_all(&read_queue);
    }
}

void pipe::close_read_end()
{
    scoped_mutex g{pipe_lock};

    if (--reader_count == 0)
    {
        broken = 1;
        wake_all(&write_queue);
    }
}

void pipe_close(struct inode *ino)
{
    bool is_writeable = ((unsigned long) ino->i_helper) & PIPE_WRITEABLE;
    pipe *p = get_pipe(ino->i_helper);

    if (is_writeable)
    {
        p->close_write_end();
    }
    else
    {
        p->close_read_end();
    }

    p->unref();
}

short pipe::poll(void *poll_file, short events)
{
    // printk("pipe poll\n");
    short revents = 0;
    scoped_mutex g{pipe_lock};

    if (events & POLLIN)
    {
        if (can_read())
            revents |= POLLIN;
        else
            poll_wait_helper(poll_file, &read_queue);
    }

    if (events & POLLOUT)
    {
        if (can_write())
            revents |= POLLOUT;
        else
            poll_wait_helper(poll_file, &write_queue);
    }

    return revents;
}

short pipe_poll(void *poll_file, short events, struct file *f)
{
    pipe *p = get_pipe(f->f_ino->i_helper);
    return p->poll(poll_file, events);
}

struct file_ops pipe_ops = {
    .read = pipe_read, .write = pipe_write, .close = pipe_close, .poll = pipe_poll};

int pipe_create(struct file **pipe_readable, struct file **pipe_writeable)
{
    /* Create the node */
    struct inode *node0 = nullptr, *node1 = nullptr;
    pipe *new_pipe = nullptr;
    struct file *rd = nullptr, *wr = nullptr;
    dentry *read_dent, *write_dent;
    node0 = inode_create(false);
    if (!node0)
        return errno = ENOMEM, -1;

    node1 = inode_create(false);
    if (!node1)
        goto err0;

    new_pipe = new pipe;
    if (!new_pipe)
    {
        goto err0;
    }

    if (!new_pipe->allocate_pipe_buffer())
    {
        goto err1;
    }

    node0->i_dev = pipedev->dev();
    node0->i_type = VFS_TYPE_CHAR_DEVICE;
    node0->i_flags = INODE_FLAG_NO_SEEK;
    node0->i_inode = current_inode_number++;
    node0->i_helper = (void *) new_pipe;
    node0->i_fops = &pipe_ops;

    /* TODO: This memcpy seems unsafe, at least... */
    memcpy(node1, node0, sizeof(*node0));
    read_dent = dentry_create("<pipe_read>", node0, nullptr);
    if (!read_dent)
        goto err1;

    write_dent = dentry_create("<pipe_write>", node1, nullptr);
    if (!write_dent)
    {
        dentry_put(read_dent);
        goto err1;
    }

    rd = inode_to_file(node0);
    if (!rd)
        goto err2;

    wr = inode_to_file(node1);
    if (!wr)
    {
        fd_put(rd);
        goto err2;
    }

    rd->f_dentry = read_dent;
    wr->f_dentry = write_dent;

    *pipe_readable = rd;
    *pipe_writeable = wr;

    /* Since malloc returns 16-byte aligned memory we can use the lower bits for stuff like this */
    node1->i_helper = (void *) ((unsigned long) new_pipe | PIPE_WRITEABLE);
    return 0;
err2:
    dentry_put(write_dent);
    dentry_put(read_dent);
err1:
    delete new_pipe;
err0:
    if (node0)
        free(node0);
    if (node1)
        free(node1);
    errno = ENOMEM;

    return -1;
}

void pipe_register_device()
{
    auto ex = dev_register_chardevs(0, 1, 0, nullptr, cul::string{"pipe"});
    if (!ex)
        panic("Could not allocate pipedev!\n");

    pipedev = ex.value();
}

INIT_LEVEL_CORE_KERNEL_ENTRY(pipe_register_device);
