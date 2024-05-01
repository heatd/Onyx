/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/console.h>
#include <onyx/irq.h>
#include <onyx/kunit.h>
#include <onyx/log.h>
#include <onyx/panic.h>
#include <onyx/timer.h>
#include <onyx/tty.h>
#include <onyx/vm.h>

#define KERN_NVAL      0xff
#define __KERN_WARN    4
#define __KERN_NOTICE  5
#define __KERN_DEFAULT __KERN_NOTICE

static struct console *cur_con __rcu;
static struct spinlock cur_con_lock;

void con_register(struct console *con)
{
    scoped_lock g{cur_con_lock};
    struct console *old = rcu_dereference(cur_con);
    if (old)
    {
        if (old->flags & CONSOLE_FLAG_VTERM && !(con->flags & CONSOLE_FLAG_VTERM))
            return;
        /* If we race last_seq_seen, it's okay, we'll just repeat a few messages */
        con->last_seq_seen = __atomic_load_n(&old->last_seq_seen, __ATOMIC_RELAXED);
        con_put(old);
    }

    rcu_assign_pointer(cur_con, con);
    con_get_rcu(cur_con);
}

static struct console *get_cur_con()
{
    struct console *con;
    rcu_read_lock();
    for (;;)
    {
        con = rcu_dereference(cur_con);
        if (!con)
            break;
        if (con_get_rcu(con))
            break;
    }
    rcu_read_unlock();
    return con;
}

struct printk_header
{
    u8 log_level;
    u16 length;
    u32 seq;
    hrtime_t timestamp;
    char data[];
};

struct printk_buf
{
    char _log_buf[LOG_BUF_SIZE];
    size_t log_tail = 0;
    size_t log_head = 0;
    unsigned int msg_seq = 0;
    static constexpr size_t logmask = LOG_BUF_SIZE - 1;

    /* Note: The functions below all require the printk_lock (or some other kind of mutual
     * exclusion) */

    u32 avail_space() const
    {
        /* Getting available space:
         * If head > tail, we're going to run into the head, so avail = head - tail mod size
         * Else we're going to run into the end of the buffer, so avail = size - (tail mod size) */
        const u32 head = log_head & logmask;
        const u32 tail = log_tail & logmask;
        const u32 avail = head > tail ? head - tail : LOG_BUF_SIZE - tail;
        DCHECK((head & (alignof(printk_header) - 1)) == 0);
        DCHECK((tail & (alignof(printk_header) - 1)) == 0);
        return avail;
    }

    bool full(u16 len) const
    {
        if (log_tail - log_head >= LOG_BUF_SIZE - len)
            return true;
        return avail_space() < len;
    }

    bool empty() const
    {
        return log_tail == log_head;
    }

    struct printk_header *get_buf(u16 len);

    void reset()
    {
        log_tail = log_head = 0;
        msg_seq = 0;
    }

    unsigned int get_seq()
    {
        return msg_seq++;
    }

    u32 find_and_print(char *buf, size_t *psize, u32 initial_seq);
};

struct printk_header *printk_buf::get_buf(u16 len)
{
    for (;;)
    {
        while (full(len))
        {
            /* If we're full, kick off other messages *IF* we're not at the tail end of the buf */
            if ((log_head & logmask) < (log_tail & logmask))
                break;
            struct printk_header *hdr = (struct printk_header *) (_log_buf + (log_head & logmask));
            DCHECK((log_head & (alignof(printk_header) - 1)) == 0);
            DCHECK(hdr->length > 0);
            log_head += hdr->length;
        }

        /* We either have enough space, or it's at the end of the buffer */
        const u32 avail = avail_space();
        struct printk_header *hdr = (struct printk_header *) (_log_buf + (log_tail & logmask));
        if (avail < len)
        {
            hdr->length = avail;
            hdr->log_level = KERN_NVAL;
        }
        else
            hdr->length = cul::align_up2(cul::min(avail, (u32) len), alignof(printk_header));

        log_tail += hdr->length;
        if (hdr->log_level != KERN_NVAL)
            return hdr;
    }
}

u32 printk_buf::find_and_print(char *buf, size_t *psize, u32 initial_seq)
{
    u32 seen = initial_seq;
    size_t head = log_head;
    size_t size = *psize;

    while (head != log_tail)
    {
        struct printk_header *header = (struct printk_header *) (_log_buf + (head & logmask));
        if (header->log_level == KERN_NVAL || header->seq < initial_seq)
        {
            /* Skip the entry */
            head += header->length;
            continue;
        }

        if (header->log_level > __KERN_WARN)
        {
            /* Skip, but take note of the seq */
            seen = header->seq + 1;
            head += header->length;
            continue;
        }

        if (head == log_head && header->seq > initial_seq)
        {
            /* Ring buffer overflow skipped N messages, register that */
            hrtime_t timestamp = clocksource_get_time();
            int written = snprintf(buf, size, "[%5ld.%06ld] console: Skipped %u messages...\n",
                                   timestamp / NS_PER_SEC, (timestamp % NS_PER_SEC) / NS_PER_US,
                                   header->seq - initial_seq);
            CHECK(written > 0);
            buf += written;
            size -= written;
            head += header->length;
            continue;
        }

        int written = snprintf(buf, size, "[%5ld.%06ld] %s", header->timestamp / NS_PER_SEC,
                               (header->timestamp % NS_PER_SEC) / NS_PER_US, header->data);
        CHECK(written > 0);

        if ((size_t) written >= size)
        {
            /* Truncated, end here */
            break;
        }

        buf += written;
        size -= written;
        seen = header->seq + 1;
        head += header->length;
    }

    *psize = *psize - size;
    return seen;
}

static struct printk_buf printk_buf;
static struct spinlock printk_lock;
#define MAX_LINE 1024
static char flush_buf[MAX_LINE];

/* XXX flush_buf locking... Put it struct console maybe */

static void flush_consoles()
{
    bool is_atomic = irq_is_disabled() || sched_is_preemption_disabled();
    struct console *con = get_cur_con();
    unsigned int write_flags = 0;
    if (is_atomic)
        write_flags |= CONSOLE_WRITE_ATOMIC;
    if (is_in_panic())
        write_flags |= CONSOLE_WRITE_PANIC;

    /* If we don't have a console, this is really early boot, and it's okay. */
    if (!con)
        return;

    if (is_atomic)
    {
        if (!mutex_trylock(&con->conlock))
        {
            /* XXX we can lose info here can't we? Is this worrying? */
            return;
        }
    }
    else
        mutex_lock(&con->conlock);

    for (;;)
    {
        /* Grab the printk lock and fetch messages */
        scoped_lock<spinlock, true> g{printk_lock};
        /* If we have seen them all, stop */
        if (con->last_seq_seen == printk_buf.msg_seq)
            break;

        /* Let's find last_seq_seen in the log buffer, and print as many messages as we can */
        size_t size = MAX_LINE;
        u32 seen = printk_buf.find_and_print(flush_buf, &size, con->last_seq_seen);
        if (size > 0)
            DCHECK(size == strlen(flush_buf));
        g.unlock();

        if (size == 0)
            continue;

        /* XXX what to do on error? */
        if (con->ops->write(flush_buf, size, write_flags, con) >= 0)
            con->last_seq_seen = seen;
        else
            break;
    }

    mutex_unlock(&con->conlock);
}

extern "C" int vprintk(const char *__restrict__ format, va_list ap)
{
    return vprintf(format, ap);
}

extern "C" int printk(const char *__restrict__ format, ...)
{
    int ret;
    va_list ap;
    va_start(ap, format);
    ret = vprintk(format, ap);
    va_end(ap);
    return ret;
}

extern "C" int vprintf(const char *__restrict__ format, va_list va)
{
    unsigned long flags = spin_lock_irqsave(&printk_lock);

    u8 log_level = __KERN_DEFAULT;

    if (format[0] == __KERN_SOH)
    {
        /* We have a log level, parse it */
        log_level = format[1] - '0';
        format += 2;
    }

    char buf[1];
    va_list vap;
    va_copy(vap, va);
    int i = vsnprintf(buf, 1, format, vap);
    CHECK(i >= 0);
    CHECK(i <= MAX_LINE);

    struct printk_header *header = printk_buf.get_buf(sizeof(struct printk_header) + i + 1);
    header->log_level = log_level;
    header->seq = printk_buf.get_seq();
    header->timestamp = clocksource_get_time();
    DCHECK(header->length >= i + sizeof(struct printk_header));
    i = vsnprintf(header->data, header->length - sizeof(struct printk_header), format, va);
    CHECK(i >= 0);
    spin_unlock_irqrestore(&printk_lock, flags);

    if (log_level <= __KERN_WARN)
        flush_consoles();
    return i;
}

extern "C" int printf(const char *__restrict__ format, ...)
{
    va_list va;
    va_start(va, format);
    int i = vprintf(format, va);
    va_end(va);
    return i;
}

void bust_printk_lock(void)
{
    printk_lock.lock = 0;
}

void kernlog_clear(void)
{
}

#define SYSLOG_ACTION_READ        2
#define SYSLOG_ACTION_READ_CLEAR  4
#define SYSLOG_ACTION_CLEAR       5
#define SYSLOG_ACTION_SIZE_BUFFER 10

int sys_syslog(int type, char *buffer, int len)
{
#if 0
    if (type == SYSLOG_ACTION_SIZE_BUFFER)
        return (int) log_tail;
    switch (type)
    {
        case SYSLOG_ACTION_READ: {
            if (copy_to_user(buffer, _log_buf, len) < 0)
                return -EFAULT;
            break;
        }
        case SYSLOG_ACTION_READ_CLEAR: {
            if (copy_to_user(buffer, _log_buf, len) < 0)
                return -EFAULT;
            kernlog_clear();
            break;
        }
        case SYSLOG_ACTION_CLEAR: {
            kernlog_clear();
            break;
        }
    }
#endif
    return 0;
}

static unsigned int log_level = LOG_LEVEL_ERROR | LOG_LEVEL_WARNING | LOG_LEVEL_FATAL;

void kernlog_set_log_level(unsigned int level)
{
    log_level = level;
}

#ifdef CONFIG_KUNIT

static struct printk_buf testbuf;

TEST(printk_buf, append)
{
    /* Check if basic message appending works */
    testbuf.reset();
    struct printk_header *hdr = testbuf.get_buf(sizeof(struct printk_header));
    ASSERT_NONNULL(hdr);
    ASSERT_EQ(testbuf.log_head, 0UL);
    ASSERT_EQ(testbuf.log_tail, sizeof(struct printk_header));
    ASSERT_EQ(hdr->length, sizeof(struct printk_header));
    hdr = testbuf.get_buf(sizeof(struct printk_header));
    ASSERT_NONNULL(hdr);
    ASSERT_EQ(testbuf.log_head, 0UL);
    ASSERT_EQ(testbuf.log_tail, sizeof(struct printk_header) * 2);
    ASSERT_EQ(hdr->length, sizeof(struct printk_header));
}

TEST(printk_buf, append_end_of_buf)
{
    /* Check if we carefully handle when we're at the end of the buffer. In such cases, we're
     * supposed to set the header log level to KERN_NVAL and overflow */
    testbuf.reset();
    struct printk_header *hdr = testbuf.get_buf(sizeof(struct printk_header) + 10);
    ASSERT_NONNULL(hdr);
    ASSERT_EQ(testbuf.log_head, 0UL);
    ASSERT_EQ(testbuf.log_tail, sizeof(struct printk_header) * 2);
    ASSERT_EQ(hdr->length, sizeof(struct printk_header) * 2);
    testbuf.log_tail = LOG_BUF_SIZE - sizeof(struct printk_header);
    struct printk_header *hdr2 = testbuf.get_buf(sizeof(struct printk_header) + 10);
    ASSERT_NONNULL(hdr2);
    ASSERT_EQ(testbuf.log_head, sizeof(struct printk_header) * 2);
    ASSERT_EQ(testbuf.log_tail, LOG_BUF_SIZE + (sizeof(struct printk_header) * 2));
    ASSERT_EQ(hdr2->length, sizeof(struct printk_header) * 2);
    struct printk_header *tail =
        (struct printk_header *) &testbuf._log_buf[LOG_BUF_SIZE - sizeof(struct printk_header)];
    ASSERT_EQ(tail->log_level, KERN_NVAL);
    ASSERT_EQ(tail->length, sizeof(struct printk_header));
}

#endif
