/*
 * Copyright (c) 2017 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
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
#include <onyx/refcount.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>
#include <onyx/types.h>
#include <onyx/utils.h>
#include <onyx/vfs.h>

#include <bits/ioctl.h>
#include <uapi/fcntl.h>
#include <uapi/poll.h>

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

    struct page *steal_page()
    {
        auto ret = page_;
        page_ = nullptr;
        return ret;
    }

    ~pipe_buffer()
    {
        if (page_)
        {
            DCHECK_PAGE(page_->ref == 1, page_);
            page_unref(page_);
        }
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

struct pipe : public refcountable
{
private:
    struct page *cached_page{nullptr};
    struct list_head pipe_buffers;
    size_t curr_len{0};
    mutex pipe_lock;

    wait_queue write_queue;
    wait_queue read_queue;

    size_t buf_size{default_pipe_size};

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

    bool may_write(bool atomic, size_t len) const
    {
        const auto avail = available_space();
        return avail > 0 && (avail >= len || !atomic);
    }

    pipe_buffer *first_buf()
    {
        return container_of(list_first_element(&pipe_buffers), pipe_buffer, list_node);
    }

    ssize_t append_iter(iovec_iter *iter, bool atomic);

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
    short poll(struct file *filp, void *poll_file, short events);
    ssize_t read_iter(iovec_iter *iter, unsigned int flags);
    ssize_t write_iter(iovec_iter *iter, int flags);

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

    int open_named(struct file *filp);
};

pipe::pipe() : refcountable(1)
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

    if (cached_page)
        page_unref(cached_page);
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
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    iovec_iter iter{cul::slice<iovec>{&iov, 1}, len, IOVEC_USER};
    return read_iter(&iter, flags);
}

ssize_t pipe::append_iter(iovec_iter *iter, bool atomic)
{
    // Logic here is a bit tricky. Try to append to the last pipe buf
    // If we can do so, then do it. Then if we still have more data, allocate a new pipe buffer
    // and append it. If we ever need to roll back (since it may be a PIPE_BUF write), do so using
    // "to_restore" and "old_restore_len".

    pipe_buffer *to_restore = nullptr;
    size_t old_restore_len = 0;
    ssize_t ret = 0;
    auto avail = available_space();

    if (!list_is_empty(&pipe_buffers))
    {
        auto last_buf = container_of(list_last_element(&pipe_buffers), pipe_buffer, list_node);
        unsigned int buf_tail = last_buf->len_ + last_buf->offset_;
        unsigned int avail_buf = min(PAGE_SIZE - buf_tail, avail);

        // See if we have space in this pipe buffer
        // TODO: Idea to test: memmove data back if we have offset != 0
        // May compact things a bit.
        if (avail_buf > 0)
        {
            // We have space, copy up
            if (atomic)
                to_restore = last_buf;

            old_restore_len = last_buf->len_;
            u8 *page_buf = (u8 *) PAGE_TO_VIRT(last_buf->page_);
            ssize_t copied = copy_from_iter(iter, page_buf + buf_tail, avail_buf);
            if (copied < 0)
                return -EFAULT;

            // Adjust the length
            last_buf->len_ += copied;
            assert(last_buf->len_ <= PAGE_SIZE);
            ret += copied;
            curr_len += copied;
            avail -= copied;
        }
    }

    // If we still have more to append and enough space, lets do so
    if (avail && !iter->empty())
    {
        if (!cached_page)
        {
            cached_page = alloc_page(GFP_KERNEL | PAGE_ALLOC_NO_ZERO);
            if (!cached_page)
            {
                ret = -ENOMEM;
                goto out;
            }
        }

        page *p = cached_page;

        auto blen = min(min(avail, iter->bytes), PAGE_SIZE);
        // Note: the page and its lifetime are now tied to the pipe buffer, but we steal
        // the page on error.
        auto buf = make_unique<pipe_buffer>(p, blen);
        if (!buf)
        {
            ret = -ENOMEM;
            goto out;
        }

        u8 *page_buf = (u8 *) PAGE_TO_VIRT(p);
        ssize_t copied = copy_from_iter(iter, page_buf, buf->len_);
        if (copied < 0)
        {
            if (atomic || !ret)
                ret = -EFAULT;
            buf->steal_page();
            goto out;
        }

        // Append the page_buf to the end of list
        list_add_tail(&buf->list_node, &pipe_buffers);
        ret += copied;
        curr_len += copied;
        to_restore = nullptr;

        // Release the cached page, definitely no longer ours.
        cached_page = nullptr;

        buf.release();
    }

    return ret;
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
    struct iovec iov;
    iov.iov_base = (void *) ubuf;
    iov.iov_len = len;
    iovec_iter iter{cul::slice<iovec>{&iov, 1}, len, IOVEC_USER};
    return write_iter(&iter, flags);
}

pipe *get_pipe(void *helper)
{
    return (pipe *) helper;
}

size_t pipe_read(size_t offset, size_t sizeofread, void *buffer, struct file *file)
{
    (void) offset;
    pipe *p = get_pipe(file->f_ino->i_pipe);
    return p->read(file->f_flags, sizeofread, buffer);
}

size_t pipe_write(size_t offset, size_t sizeofwrite, void *buffer, struct file *file)
{
    (void) offset;
    pipe *p = get_pipe(file->f_ino->i_pipe);
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

short pipe::poll(struct file *filp, void *poll_file, short events)
{
    short revents = 0;
    const bool wr = fd_may_access(filp, FILE_ACCESS_WRITE);
    const bool rd = fd_may_access(filp, FILE_ACCESS_READ);

    scoped_mutex g{pipe_lock};

    if (rd)
    {
        if (events & (POLLIN | POLLRDNORM))
        {
            if (can_read())
                revents |= (events & (POLLIN | POLLRDNORM));
        }

        if (writer_count == 0)
            revents |= POLLHUP;
    }

    if (wr)
    {
        if (events & (POLLOUT | POLLWRNORM))
        {
            if (can_write())
                revents |= (events & (POLLOUT | POLLWRNORM));
        }

        if (reader_count == 0)
            revents |= POLLERR;
    }

    if (revents == 0)
    {
        if (rd)
            poll_wait_helper(poll_file, &read_queue);
        if (wr)
            poll_wait_helper(poll_file, &write_queue);
    }

    return revents;
}

static short pipe_poll(void *poll_file, short events, struct file *f)
{
    pipe *p = get_pipe(f->f_ino->i_pipe);
    return p->poll(f, poll_file, events);
}

static unsigned int pipe_ioctl(int req, void *argp, struct file *f)
{
    auto p = get_pipe(f->f_ino->i_pipe);

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
    auto p = get_pipe(f->f_ino->i_pipe);

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
    pipe *p = get_pipe(filp->f_ino->i_pipe);

    if (fd_may_access(filp, FILE_ACCESS_READ))
        p->close_read_end();

    if (fd_may_access(filp, FILE_ACCESS_WRITE))
        p->close_write_end();
    p->unref();
}

ssize_t pipe::read_iter(iovec_iter *iter, unsigned int flags)
{
    ssize_t ret = 0;

    scoped_mutex g{pipe_lock};

    bool wasfull = available_space() < PIPE_BUF;

    while (!iter->empty())
    {
        if (!can_read())
        {
            if (ret || writer_count == 0)
                break;

            if (flags & O_NONBLOCK)
            {
                if (!ret)
                    ret = -EAGAIN;
                break;
            }

            if (wait_for_event_mutex_interruptible(&read_queue, can_read_or_eof(), &pipe_lock) ==
                -ERESTARTSYS)
            {
                ret = ret ?: -ERESTARTSYS;
                break;
            }

            wasfull = available_space() < PIPE_BUF;
            continue;
        }

        assert(!list_is_empty(&pipe_buffers));

        // Consume the first buffer
        auto pbf = first_buf();
        u8 *page_buf = (u8 *) PAGE_TO_VIRT(pbf->page_) + pbf->offset_;

        ssize_t copied = copy_to_iter(iter, page_buf, pbf->len_);
        if (copied < 0)
        {
            if (!ret)
                ret = -EFAULT;
            break;
        }

        pbf->offset_ += copied;
        pbf->len_ -= copied;

        if (pbf->len_ == 0)
        {
            // If its now empty, free the pipe buffer
            list_remove(&pbf->list_node);

            // Check if we have a cached page. If not, cache this one, else let it go.
            if (!cached_page)
            {
                cached_page = pbf->steal_page();
            }

            delete pbf;
        }

        // Decrement the length of the pipe
        // No need to advance iter, since copy_to_iter does that
        curr_len -= copied;
        ret += copied;

        if (!can_read())
        {
            // Nothing more to read
            break;
        }
    }

    g.unlock();

    if (wasfull && ret > 0)
    {
        // If it was previously full and we read some, wake the writers
        wake_all(&write_queue);
    }

    return ret;
}

ssize_t pipe::write_iter(iovec_iter *iter, int flags)
{
    bool is_atomic_write = iter->bytes <= PIPE_BUF;
    ssize_t ret = 0;

    scoped_mutex g{pipe_lock};

    bool wasempty = !can_read();

    while (!iter->empty())
    {
        if (reader_count == 0)
        {
            CALL_KUNIT_MOCKABLE(kernel_raise_signal, SIGPIPE, get_current_process(), 0, nullptr);

            if (!ret)
                ret = -EPIPE;
            break;
        }

        if (!may_write(is_atomic_write, iter->bytes))
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
                    &write_queue, may_write(is_atomic_write, iter->bytes) || reader_count == 0,
                    &pipe_lock) == -ERESTARTSYS)
            {
                if (!ret)
                    ret = -ERESTARTSYS;
                break;
            }

            wasempty = !can_read();
            continue;
        }

        // Now we have space
        ssize_t st = append_iter(iter, is_atomic_write);

        if (st < 0)
        {
            if (!ret)
                ret = st;
            break;
        }

        ret += st;
    }

    if (wasempty && ret > 0)
        wake_all(&read_queue);

    return ret;
}

ssize_t pipe_read_iter(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    (void) off;
    (void) flags;
    pipe *p = get_pipe(filp->f_ino->i_pipe);
    return p->read_iter(iter, filp->f_flags);
}

ssize_t pipe_write_iter(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    (void) off;
    (void) flags;
    pipe *p = get_pipe(filp->f_ino->i_pipe);
    return p->write_iter(iter, filp->f_flags);
}

const struct file_ops pipe_ops = {
    .read = pipe_read,
    .write = pipe_write,
    .ioctl = pipe_ioctl,
    .poll = pipe_poll,
    .fcntl = pipe_fcntl,
    .release = pipe_release,
    .read_iter = pipe_read_iter,
    .write_iter = pipe_write_iter,
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
    anon_pipe_ino->i_mode = S_IFIFO;
    anon_pipe_ino->i_flags = INODE_FLAG_NO_SEEK;
    anon_pipe_ino->i_inode = current_inode_number++;
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
    dget(anon_pipe_dent);
    dget(anon_pipe_dent);
    inode_ref(anon_pipe_ino);

    *pipe_readable = rd;
    *pipe_writeable = wr;

    new_pipe.ref();
    anon_pipe_ino->i_pipe = new_pipe.release();

    return 0;
err2:
    dput(anon_pipe_dent);
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

int named_pipe_open(struct file *f);

void named_pipe_release(struct file *filp);

const struct file_ops named_pipe_ops = {
    .read = pipe_read,
    .write = pipe_write,
    .ioctl = pipe_ioctl,
    .on_open = named_pipe_open,
    .poll = pipe_poll,
    .fcntl = pipe_fcntl,
    .release = named_pipe_release,
};

void named_pipe_release(struct file *filp)
{
    pipe *p = get_pipe(filp->f_ino->i_pipe);

    if (fd_may_access(filp, FILE_ACCESS_READ))
        p->close_read_end();

    if (fd_may_access(filp, FILE_ACCESS_WRITE))
        p->close_write_end();

    p->unref();

    if (p->reader_count + p->writer_count == 0)
    {
        // Let's attempt to free the pipe, but first lock the inode
        scoped_lock g{filp->f_ino->i_lock};

        // Re-check under the lock
        if (p->reader_count + p->writer_count == 0)
        {
            // Free the pipe, undo file_ops
            p->unref();
            filp->f_ino->i_pipe = nullptr;
        }
    }
}

int named_pipe_open(struct file *f)
{
    // Lets attempt to grab a pipe for our inode
    // Note that we do not need a hashtable or tree
    // of any kind for the inode, because as long as
    // a pipe is alive, so is its struct inode.
    auto ino = f->f_ino;

    scoped_lock g{ino->i_lock};

    pipe *p = ino->i_pipe;

    if (!p)
    {
        // Not found, create a new pipe
        p = new pipe{};
        if (!p)
            return -ENOMEM;
        // And set the readers/writers to 0, 0
        p->reader_count = p->writer_count = 0;
        ino->i_pipe = p;
    }

    // ref the pipe and unlock the inode
    p->ref();

    g.unlock();

    int st = p->open_named(f);
    if (st < 0)
    {
        // Attempt to revert our changes
        g.lock();

        if (p->reader_count + p->writer_count == 0)
        {
            // Unused, we can free
            p->unref();
            ino->i_pipe = nullptr;
        }

        g.unlock();

        p->unref();
    }

    return 0;
}

int pipe::open_named(struct file *filp)
{
    scoped_mutex g{pipe_lock};
    ssize_t st = 0;

    // As per standard named pipe behavior, block until a peer shows up
    if ((filp->f_flags & O_RDWRMASK) == O_RDONLY)
    {
        reader_count++;
        wake_all(&write_queue);
        COMPILER_BARRIER();
        if (!(filp->f_flags & O_NONBLOCK))
            st = wait_for_event_mutex_interruptible(&read_queue, writer_count != 0, &pipe_lock);
    }
    else if ((filp->f_flags & O_RDWRMASK) == O_WRONLY)
    {
        writer_count++;
        wake_all(&read_queue);
        COMPILER_BARRIER();
        // Use a lambda to go around the multiple wait_for_event problem
        if (!(filp->f_flags & O_NONBLOCK))
            st = [&]() REQUIRES(pipe_lock) -> ssize_t {
                return wait_for_event_mutex_interruptible(&write_queue, reader_count != 0,
                                                          &pipe_lock);
            }();
    }
    else if ((filp->f_flags & O_RDWRMASK) == O_RDWR)
    {
        // POSIX leaves this undefined, we peer with ourselves.
        writer_count++;
        reader_count++;
        st = 0;
    }
    else
    {
        assert(0);
    }

    if (st < 0)
    {
        // Remove ourselves from the count if we got a signal
        if (filp->f_flags & O_WRONLY)
            writer_count--;
        else
            reader_count--;
    }

    return st;
}

int pipe_do_fifo(inode *ino)
{
    ino->i_fops = (file_ops *) &named_pipe_ops;
    return 0;
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

TEST(pipe, readv_works)
{
    auto_addr_limit l_{VM_KERNEL_ADDR_LIMIT};
    auto p = make_refc<pipe>();
    p->reader_count = 1;
    p->writer_count = 1;

    char teststr[] = {'1', '1', '1', '1'};
    p->write(0, 2, teststr);

    iovec iov[2];
    iov[0].iov_base = teststr;
    iov[0].iov_len = 2;
    iov[1].iov_base = teststr + 2;
    iov[1].iov_len = 2;

    cul::slice<iovec> sl(iov, 2);
    iovec_iter iter(sl, 4, IOVEC_KERNEL);

    ssize_t total_read = p->read_iter(&iter, O_NONBLOCK);

    EXPECT_EQ(total_read, 2);
}

#endif
