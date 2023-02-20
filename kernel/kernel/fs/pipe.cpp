/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
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
#include <onyx/kunit.h>
#include <onyx/limits.h>
#include <onyx/mm/slab.h>
#include <onyx/panic.h>
#include <onyx/poll.h>
#include <onyx/process.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>
#include <onyx/types.h>
#include <onyx/utils.h>
#include <onyx/vfs.h>

#include <bits/ioctl.h>

#include <onyx/list.hpp>

static chardev *pipedev = nullptr;
static atomic<ino_t> current_inode_number = 0;

constexpr unsigned long default_pipe_size = (16 * PAGE_SIZE);
// TODO: Make this configurable
constexpr unsigned long max_pipe_size = 0x100000;

static slab_cache *pipe_buffer_cache, *pipe_cache;

struct pipe_buffer
{
    struct page *page_;
    struct list_head list_node;
    unsigned int len_;
    unsigned int offset_{0};

    pipe_buffer(struct page *page, unsigned int len) : page_{page}, len_{len}
    {
    }

    pipe_buffer() = delete;

    CLASS_DISALLOW_COPY(pipe_buffer);
    CLASS_DISALLOW_MOVE(pipe_buffer);

    ~pipe_buffer()
    {
        page_unref(page_);
    }

    void *operator new(size_t len)
    {
        return kmem_cache_alloc(pipe_buffer_cache, 0);
    }

    void operator delete(void *ptr)
    {
        kmem_cache_free(pipe_buffer_cache, ptr);
    }
};

class pipe : public refcountable
{
private:
    struct list_head pipe_buffers;
    size_t buf_size{default_pipe_size};
    size_t curr_len{0};
    mutex pipe_lock;

    wait_queue write_queue;
    wait_queue read_queue;

    bool can_read() const
    {
        return curr_len != 0;
    }

    bool can_read_or_eof() const
    {
        return can_read() || writer_count == 0;
    }

    bool can_write() const
    {
        return curr_len < buf_size;
    }

    bool can_write_or_broken() const
    {
        return curr_len < buf_size || reader_count == 0;
    }

    pipe_buffer *first_buf()
    {
        return container_of(list_first_element(&pipe_buffers), pipe_buffer, list_node);
    }

    ssize_t append(const void *ubuf, size_t len, bool atomic);

public:
    size_t reader_count{1};
    size_t writer_count{1};
    pipe();
    ~pipe() override;
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

    size_t get_unread_len() const
    {
        return curr_len;
    }

    void *operator new(size_t len)
    {
        return kmem_cache_alloc(pipe_cache, 0);
    }

    void operator delete(void *ptr)
    {
        kmem_cache_free(pipe_cache, ptr);
    }

    void set_max_length(size_t len)
    {
        buf_size = len;
    }

    int get_capacity();
    int set_capacity(size_t len);
};

pipe::pipe() : refcountable(2)
{
    init_wait_queue_head(&write_queue);
    init_wait_queue_head(&read_queue);
    INIT_LIST_HEAD(&pipe_buffers);
}

pipe::~pipe()
{
    list_for_every_safe (&pipe_buffers)
    {
        auto pbf = container_of(l, struct pipe_buffer, list_node);

        list_remove(&pbf->list_node);
        delete pbf;
    }
}

bool pipe::is_full() const
{
    return buf_size <= curr_len;
}

size_t pipe::available_space() const
{
    return buf_size < curr_len ? 0 : buf_size - curr_len;
}

ssize_t pipe::read(int flags, size_t len, void *buf)
{
    ssize_t ret = 0;

    if (len == 0)
        return 0;

    scoped_mutex g{pipe_lock};

    // Lets keep track if the pipe was full the last time we grabbed the lack
    // By doing so, we can know when to wake writers instead of wasting time trying to do so
    // for no reason.
    // Since PIPE_BUF atomic writes are complicated with this scheme, we add PIPE_BUF slack.
    bool wasfull = available_space() < PIPE_BUF;

    while (true)
    {
        if (!can_read())
        {
            // If we can't read more, return the short read if we have read some
            if (ret || writer_count == 0)
            {
                break;
            }

            // NONBLOCK = return short read (already handled) or EAGAIN
            if (flags & O_NONBLOCK)
            {
                if (!ret)
                    ret = -EAGAIN;
                break;
            }

            // Wait for writers
            if (wait_for_event_mutex_interruptible(&read_queue, can_read_or_eof(), &pipe_lock) ==
                -EINTR)
            {
                ret = ret ?: -EINTR;
                break;
            }

            wasfull = available_space() < PIPE_BUF;

            continue;
        }

        /* We have data, lets read some */
        assert(!list_is_empty(&pipe_buffers));

        // Consume the first buffer in the queue

        auto pbf = first_buf();

        size_t to_read = min((size_t) pbf->len_, len);

        u8 *page_buf = (u8 *) PAGE_TO_VIRT(pbf->page_) + pbf->offset_;

        if (copy_to_user((u8 *) buf + ret, page_buf, to_read) < 0)
        {
            if (!ret)
                ret = -EFAULT;
            break;
        }

        pbf->offset_ += to_read;
        pbf->len_ -= to_read;

        if (pbf->len_ == 0)
        {
            // If its now empty, free the pipe buffer
            list_remove(&pbf->list_node);
            delete pbf;
        }

        // Decrement the length of the pipe (curr_len)
        curr_len -= to_read;
        ret += to_read;
        len -= to_read;

        if (!len || !can_read())
        {
            // No more to read, break
            break;
        }
    }

    // Unlock to prevent contention with writers
    g.unlock();

    if (wasfull && ret > 0)
    {
        // If it was previously full and we read some, wake the writers
        wake_all(&write_queue);
    }

    return ret;
}

ssize_t pipe::append(const void *ubuf, size_t len, bool atomic)
{
    // Logic here is a bit tricky. Try to append to the last pipe buf
    // If we can do so, then do it. Then if we still have more data, allocate a new pipe buffer
    // and append it. If we ever need to roll back (since it may be a PIPE_BUF write), do so using
    // "to_restore" and "old_restore_len".

    pipe_buffer *to_restore = nullptr;
    size_t old_restore_len = 0;
    ssize_t ret = 0;

    if (!list_is_empty(&pipe_buffers))
    {
        auto last_buf = container_of(list_last_element(&pipe_buffers), pipe_buffer, list_node);

        // See if we have space in this pipe buffer
        // TODO: Idea to test: memmove data back if we have offset != 0
        // May compact things a bit.
        if (PAGE_SIZE - last_buf->len_ <= len)
        {
            // We have space, copy up
            if (atomic)
                to_restore = last_buf;

            old_restore_len = last_buf->len_;
            u8 *page_buf = (u8 *) PAGE_TO_VIRT(last_buf->page_);
            size_t to_copy = min(PAGE_SIZE - last_buf->len_, len);
            if (copy_from_user(page_buf + last_buf->offset_, ubuf, to_copy) < 0)
                return -EFAULT;

            // Adjust the length
            last_buf->len_ += to_copy;
            assert(last_buf->len_ <= PAGE_SIZE);
            len -= to_copy;
            ret += to_copy;
            curr_len += to_copy;
        }
    }

    const auto avail = available_space();

    // If we still have more to append and enough space, lets do so
    if (avail && len)
    {
        page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
        if (!p)
        {
            ret = -ENOMEM;
            goto out;
        }

        auto blen = min(min(avail, len), PAGE_SIZE);
        // Note: the page and its lifetime are now tied to the pipe buffer
        auto buf = make_unique<pipe_buffer>(p, blen);
        if (!buf)
        {
            ret = -ENOMEM;
            free_page(p);
            goto out;
        }

        u8 *page_buf = (u8 *) PAGE_TO_VIRT(p);
        if (copy_from_user(page_buf, (u8 *) ubuf + ret, buf->len_) < 0)
        {
            if (atomic || !ret)
                ret = -EFAULT;
            goto out;
        }

        // Append the page_buf to the end of list
        list_add_tail(&buf->list_node, &pipe_buffers);
        ret += buf->len_;
        curr_len += buf->len_;
        to_restore = nullptr;

        buf.release();
    }

out:
    if (atomic && to_restore)
    {
        curr_len -= (to_restore->len_ - old_restore_len);
        to_restore->len_ = old_restore_len;
    }

    return ret;
}

// Pretty basic mocking thing
// I don't know if this is any useful honestly.
// The "easiest" way would be to hot-patch the functions we want to mock with a jmp

#ifdef CONFIG_KUNIT
#define KUNIT_MOCKABLE(name, ret, ...) ret (*name##_MOCK)(__VA_ARGS__) = name;
#define CALL_KUNIT_MOCKABLE(name, ...) (name##_MOCK)(__VA_ARGS__)
#else
#define KUNIT_MOCKABLE(name, ret, ...)
#define CALL_KUNIT_MOCKABLE(name, ...) (name)(__VA_ARGS__)
#endif

KUNIT_MOCKABLE(kernel_raise_signal, int, int, process *, unsigned int, siginfo_t *);

ssize_t pipe::write(int flags, size_t len, const void *ubuf)
{
    bool is_atomic_write = len <= PIPE_BUF;
    ssize_t ret = 0;

    scoped_mutex g{pipe_lock};

    bool wasempty = !can_read();

    while (len)
    {
        if (reader_count == 0)
        {
            CALL_KUNIT_MOCKABLE(kernel_raise_signal, SIGPIPE, get_current_process(), 0, nullptr);

            if (!ret)
                ret = -EPIPE;
            break;
        }

        const auto avail = available_space();

        bool may_write = avail > 0;

        if (avail < len && is_atomic_write)
            may_write = false;

        if (!may_write)
        {
            if (ret != 0)
            {
                /* now that we're blocking, might as well signal readers */
                wake_all(&read_queue);
            }

            if (flags & O_NONBLOCK)
            {
                if (!ret)
                    ret = -EAGAIN;
                break;
            }

            if (wait_for_event_mutex_interruptible(
                    &write_queue,
                    (is_atomic_write && available_space() >= (len - ret)) || !is_full() ||
                        reader_count == 0,
                    &pipe_lock) == -EINTR)
            {
                if (!ret)
                    ret = -EINTR;
                break;
            }

            wasempty = !can_read();
            continue;
        }

        // Ok, we have space, lets write
        ssize_t st = append((const u8 *) ubuf + ret, min(avail, len), is_atomic_write);

        if (st < 0)
        {
            if (!ret)
                ret = st;
            break;
        }

        ret += st;
        len -= st;
    }

    /* After finishing the write, signal any possible readers */
    if (wasempty && ret > 0)
        wake_all(&read_queue);

    return ret;
}

pipe *get_pipe(void *helper)
{
    return (pipe *) helper;
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
    scoped_mutex g{pipe_lock};
    /* wake up any possibly-blocked writers */
    if (--writer_count == 0)
    {
        wake_all(&read_queue);
    }
}

void pipe::close_read_end()
{
    scoped_mutex g{pipe_lock};
    if (--reader_count == 0)
    {
        wake_all(&write_queue);
    }
}

void pipe_close(struct inode *ino)
{
    pipe *p = get_pipe(ino->i_helper);

    assert(p->writer_count == 0);
    assert(p->reader_count == 0);
    printk("pipe close\n");

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

static short pipe_poll(void *poll_file, short events, struct file *f)
{
    pipe *p = get_pipe(f->f_ino->i_helper);
    return p->poll(poll_file, events);
}

static unsigned int pipe_ioctl(int req, void *argp, struct file *f)
{
    auto p = get_pipe(f->f_ino->i_helper);

    switch (req)
    {
        case FIONREAD: {
            auto len = (int) cul::clamp(p->get_unread_len(), (size_t) INT_MAX);
            return copy_to_user(argp, &len, sizeof(int));
        }
    }

    return -ENOTTY;
}

int pipe::get_capacity()
{
    return buf_size;
}

int pipe::set_capacity(size_t len)
{
    // PIPE_BUF is the minimum buffer size, per POSIX
    if (len < PIPE_BUF)
        len = PIPE_BUF;

    // Clamp to int as some interfaces (FIONREAD, fcntl) may struggle with larger than int
    // sizes and lengths.
    if (len > INT_MAX)
        len = INT_MAX;

    if (len > max_pipe_size)
        len = max_pipe_size;

    scoped_mutex g{pipe_lock};

    buf_size = len;

    // Wake up any writers
    wake_all(&write_queue);
    return 0;
}

static int pipe_fcntl(struct file *f, int cmd, unsigned long arg)
{
    auto p = get_pipe(f->f_ino->i_helper);

    switch (cmd)
    {
        case F_GETPIPE_SZ:
            return p->get_capacity();
        case F_SETPIPE_SZ:
            return p->set_capacity(arg);
    }

    return -EINVAL;
}

void pipe_release(struct file *filp)
{
    pipe *p = get_pipe(filp->f_ino->i_helper);

    if (fd_may_access(filp, FILE_ACCESS_READ))
        p->close_read_end();

    if (fd_may_access(filp, FILE_ACCESS_WRITE))
        p->close_write_end();
}

const struct file_ops pipe_ops = {
    .read = pipe_read,
    .write = pipe_write,
    .close = pipe_close,
    .ioctl = pipe_ioctl,
    .poll = pipe_poll,
    .fcntl = pipe_fcntl,
    .release = pipe_release,
};

static int pipe_create(struct file **pipe_readable, struct file **pipe_writeable)
{
    /* Create the node */
    struct inode *anon_pipe_ino = nullptr;
    ref_guard<pipe> new_pipe;
    struct file *rd = nullptr, *wr = nullptr;
    dentry *anon_pipe_dent;
    int ret = -ENOMEM;

    anon_pipe_ino = inode_create(false);
    if (!anon_pipe_ino)
        return -ENOMEM;

    new_pipe = make_refc<pipe>();
    if (!new_pipe)
    {
        goto err0;
    }

    anon_pipe_ino->i_dev = pipedev->dev();
    anon_pipe_ino->i_type = VFS_TYPE_FIFO;
    anon_pipe_ino->i_flags = INODE_FLAG_NO_SEEK;
    anon_pipe_ino->i_inode = current_inode_number++;
    // write end is set down there
    anon_pipe_ino->i_helper = (void *) new_pipe.get();
    anon_pipe_ino->i_fops = (struct file_ops *) &pipe_ops;

    anon_pipe_dent = dentry_create("<anon_pipe>", anon_pipe_ino, nullptr);
    if (!anon_pipe_dent)
        goto err0;

    rd = inode_to_file(anon_pipe_ino);
    if (!rd)
        goto err2;

    wr = inode_to_file(anon_pipe_ino);
    if (!wr)
    {
        fd_put(rd);
        goto err2;
    }

    rd->f_dentry = anon_pipe_dent;
    wr->f_dentry = anon_pipe_dent;

    // Get new refs for the second fd
    dentry_get(anon_pipe_dent);
    inode_ref(anon_pipe_ino);

    *pipe_readable = rd;
    *pipe_writeable = wr;

    anon_pipe_ino->i_helper = (void *) new_pipe.release();

    new_pipe.release();

    return 0;
err2:
    dentry_put(anon_pipe_dent);
err0:
    if (anon_pipe_ino)
        close_vfs(anon_pipe_ino);
    return ret;
}

static void pipe_init()
{
    auto ex = dev_register_chardevs(0, 1, 0, nullptr, cul::string{"pipe"});
    if (!ex)
        panic("Could not allocate pipedev!\n");

    pipedev = ex.value();

    pipe_cache = kmem_cache_create("pipe", sizeof(pipe), 0, 0, nullptr);
    if (!pipe_cache)
        panic("Could not create pipe cache\n");

    pipe_buffer_cache = kmem_cache_create("pipe_buffer", sizeof(pipe_buffer), 0, 0, nullptr);
    if (!pipe_buffer_cache)
        panic("Could not create pipe_buffer cache\n");
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(pipe_init);

// TODO: O_DIRECT
#define PIPE2_VALID_FLAGS (O_CLOEXEC | O_NONBLOCK)

int sys_pipe2(int *upipefd, int flags)
{
    int pipefd[2] = {-1, -1};
    int st = 0;

    if (flags & ~PIPE2_VALID_FLAGS)
        return -EINVAL;

    /* Create the pipe */
    struct file *read_end, *write_end;

    if (st = pipe_create(&read_end, &write_end); st < 0)
    {
        return st;
    }

    pipefd[0] = open_with_vnode(read_end, O_RDONLY | flags);
    if (pipefd[0] < 0)
    {
        st = -errno;
        goto error;
    }

    pipefd[1] = open_with_vnode(write_end, O_WRONLY | flags);
    if (pipefd[1] < 0)
    {
        st = -errno;
        goto error;
    }

    if (copy_to_user(upipefd, pipefd, sizeof(int) * 2) < 0)
    {
        st = -EFAULT;
        goto error;
    }

    fd_put(read_end);
    fd_put(write_end);

    return 0;
error:
    fd_put(read_end);
    fd_put(write_end);

    if (pipefd[0] != -1)
        file_close(pipefd[0]);
    if (pipefd[1] != -1)
        file_close(pipefd[1]);

    return -st;
}

int sys_pipe(int *upipefds)
{
    return sys_pipe2(upipefds, 0);
}

#ifdef CONFIG_KUNIT

TEST(pipe, rw_works)
{
    auto_addr_limit l_{VM_KERNEL_ADDR_LIMIT};

    auto p = make_refc<pipe>();

    const char *h = "Hello";
    const size_t len = strlen(h) + 1;
    ssize_t st = p->write(0, len, h);

    ASSERT_EQ(st, (ssize_t) len);
    ASSERT_EQ(p->get_unread_len(), len);

    char buf[len];
    st = p->read(0, PAGE_SIZE, buf);

    ASSERT_EQ(st, (ssize_t) len);
    ASSERT_EQ(p->get_unread_len(), 0U);
}

TEST(pipe, pipe_buf_works)
{
    auto_addr_limit l_{VM_KERNEL_ADDR_LIMIT};

    auto p = make_refc<pipe>();

    p->set_max_length(1);

    const char *h = "Hello";
    const size_t len = strlen(h) + 1;
    ssize_t st = p->write(O_NONBLOCK, len, h);

    ASSERT_EQ(st, -EAGAIN);
    ASSERT_EQ(p->get_unread_len(), 0U);

    st = p->write(O_NONBLOCK, 1, h);
    ASSERT_EQ(st, 1);
    ASSERT_EQ(p->get_unread_len(), 1U);

    st = p->write(O_NONBLOCK, 1, h);

    ASSERT_EQ(st, -EAGAIN);
    ASSERT_EQ(p->get_unread_len(), 1U);
}

TEST(pipe, eof_works)
{
    auto_addr_limit l_{VM_KERNEL_ADDR_LIMIT};

    auto p = make_refc<pipe>();
    p->writer_count = 0;

    char c;
    ssize_t st = p->read(0, 1, &c);

    EXPECT_EQ(st, 0);

    st = p->read(O_NONBLOCK, 1, &c);
    EXPECT_EQ(st, 0);
}

TEST(pipe, broken_pipe)
{
    auto_addr_limit l_{VM_KERNEL_ADDR_LIMIT};

    auto p = make_refc<pipe>();
    p->reader_count = 0;

    auto original = kernel_raise_signal_MOCK;
    kernel_raise_signal_MOCK = [](int, process *, unsigned, siginfo_t *) -> int { return 0; };

    char c = 'A';

    ssize_t st = p->write(0, 1, &c);

    kernel_raise_signal_MOCK = original;

    EXPECT_EQ(st, -EPIPE);
    EXPECT_EQ(p->get_unread_len(), 0U);
}

#endif
