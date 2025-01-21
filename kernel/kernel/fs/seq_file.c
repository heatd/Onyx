/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/dentry.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/mm/slab.h>
#include <onyx/rculist.h>
#include <onyx/seq_file.h>

static struct slab_cache *seq_file_cache;

int seq_open(struct file *filp, const struct seq_operations *ops)
{
    struct seq_file *seq;

    seq = kmem_cache_alloc(seq_file_cache, GFP_KERNEL);
    if (!seq)
        return -ENOMEM;

    seq->buf = NULL;
    seq->count = seq->size = seq->from = seq->index = 0;
    seq->file = filp;
    mutex_init(&seq->lock);
    seq->op = ops;
    seq->private = NULL;

    // WARN_ON(filp->private_data);
    filp->private_data = seq;
    return 0;
}

static void *seq_buf_alloc(size_t len)
{
    /* TODO: kvmalloc */
    return kmalloc(len, GFP_KERNEL);
}

static int seq_buf_realloc(struct seq_file *seq)
{
    void *ptr = krealloc(seq->buf, seq->size << 1, GFP_KERNEL);
    if (!ptr)
        return -ENOMEM;
    seq->buf = ptr;
    seq->size <<= 1;
    return 0;
}

ssize_t seq_read_iter(struct file *filp, size_t off, struct iovec_iter *iter, unsigned int flags)
{
    struct seq_file *seq = filp->private_data;
    ssize_t copied = 0;
    ssize_t err = 0;
    void *ptr;

    mutex_lock(&seq->lock);

    if (!seq->buf)
    {
        /* No buf? Allocate */
        copied = -ENOMEM;
        seq->buf = seq_buf_alloc(PAGE_SIZE);
        if (!seq->buf)
            goto out;
        seq->size = PAGE_SIZE;
        copied = 0;
    }

    if (seq->count > 0)
    {
        copied = copy_to_iter(iter, seq->buf + seq->from, seq->count);
        if (copied > 0)
        {
            seq->from += copied;
            seq->count -= copied;
        }

        /* Didn't read everything, bail */
        if (seq->count > 0)
            goto out;
    }

    seq->from = 0;
    ptr = seq->op->start(seq, &seq->index);
    for (;;)
    {
        ssize_t shown;
        if (!ptr)
            copied = copied ?: 0;
        if (IS_ERR(ptr))
            copied = copied ?: PTR_ERR(ptr);
        if (!ptr || IS_ERR(ptr))
            goto err;

        shown = seq->op->show(seq, ptr);
        if (shown < 0)
            goto out;
        if (shown > 0)
        {
            seq->count = 0;
            ptr = seq->op->next(seq, ptr, &seq->index);
            continue;
        }

        copied += shown;
        if (!seq_has_overflowed(seq))
            break;
        seq->op->stop(seq, ptr);
        seq->count = 0;
        if (seq_buf_realloc(seq) < 0)
        {
            copied = copied ?: -ENOMEM;
            goto out;
        }

        ptr = seq->op->start(seq, &seq->index);
    }

    /* We have one record read, now try to get more, if we can */
    for (;;)
    {
        ssize_t shown;
        size_t old_count = seq->count;
        ptr = seq->op->next(seq, ptr, &seq->index);
        if (IS_ERR_OR_NULL(ptr))
            break;
        shown = seq->op->show(seq, ptr);
        if (shown > 0)
        {
            /* Skip */
            seq->count = old_count;
        }
        else if (shown < 0 || seq_has_overflowed(seq))
        {
            seq->count = old_count;
            break;
        }
    }

    seq->op->stop(seq, ptr);
    err = copy_to_iter(iter, seq->buf + seq->from, seq->count);
    if (err >= 0)
    {
        copied += err;
        seq->count -= err;
        seq->from += err;
    }

    copied = copied ?: err;
    goto out;
err:
    seq->op->stop(seq, ptr);
    seq->count = 0;
out:
    mutex_unlock(&seq->lock);
    return copied;
}
off_t seq_lseek(struct file *, off_t, int);
void seq_release(struct file *filp)
{
    struct seq_file *seq = filp->private_data;
    kfree(seq->buf);
    kmem_cache_free(seq_file_cache, seq);
}

static void seq_set_overflow(struct seq_file *m)
{
    m->count = m->size;
}

int seq_putc(struct seq_file *m, char c)
{
    if (m->count < m->size)
    {
        m->buf[m->count++] = c;
        return 0;
    }

    seq_set_overflow(m);
    return -EOVERFLOW;
}

int seq_puts(struct seq_file *m, const char *s)
{
    size_t len = strlen(s);
    if (m->count + len < m->size)
    {
        memcpy(m->buf + m->count, s, len);
        m->count += len;
        return 0;
    }

    seq_set_overflow(m);
    return -EOVERFLOW;
}

int seq_printf(struct seq_file *m, const char *s, ...)
{
    int written;
    va_list va;

    if (seq_has_overflowed(m))
        return -EOVERFLOW;

    va_start(va, s);
    written = vsnprintf(m->buf + m->count, m->size - m->count - 1, s, va);
    va_end(va);
    if (written < 0 || (unsigned int) written > m->size - m->count - 1)
    {
        seq_set_overflow(m);
        return -EOVERFLOW;
    }

    m->count += written;
    return 0;
}

struct list_head *seq_list_start(struct list_head *head, off_t pos)
{
    list_for_every (head)
        if (pos-- == 0)
            return l;

    return NULL;
}

struct list_head *seq_list_start_head(struct list_head *head, off_t pos)
{
    if (!pos)
        return head;

    return seq_list_start(head, pos - 1);
}

struct list_head *seq_list_next(void *v, struct list_head *head, off_t *ppos)
{
    struct list_head *lh;

    lh = ((struct list_head *) v)->next;
    ++*ppos;
    return lh == head ? NULL : lh;
}

struct list_head *seq_list_start_rcu(struct list_head *head, off_t pos)
{
    list_for_every_rcu (head)
        if (pos-- == 0)
            return l;

    return NULL;
}

struct list_head *seq_list_start_head_rcu(struct list_head *head, off_t pos)
{
    if (!pos)
        return head;

    return seq_list_start_rcu(head, pos - 1);
}

struct list_head *seq_list_next_rcu(void *v, struct list_head *head, off_t *ppos)
{
    struct list_head *lh;

    lh = READ_ONCE(((struct list_head *) v)->next);
    ++*ppos;
    return lh == head ? NULL : lh;
}

int seq_d_path_under_root(struct seq_file *m, const struct path *path, const struct path *root)
{
    char *buf = NULL, *p;
    int len = 0;
    int pathlen = 0;
    if (seq_has_overflowed(m))
        return -EOVERFLOW;

    len = m->size - m->count;
    buf = m->buf + m->count;

    p = d_path_under_root(path, NULL, buf, len);
    if (IS_ERR(p))
        return PTR_ERR(p);
    if (!p)
        return SEQ_SKIP;

    pathlen = strlen(p);
    memmove(buf, p, pathlen);
    m->count += pathlen;
    return 0;
}

static void *single_start(struct seq_file *m, off_t *off)
{
    return *off ? NULL : SEQ_START_TOKEN;
}

static void *single_next(struct seq_file *m, void *ptr, off_t *off)
{
    (*off)++;
    return NULL;
}

static void single_stop(struct seq_file *m, void *ptr)
{
}

int single_open(struct file *filp, int (*show)(struct seq_file *, void *), void *data)
{
    struct seq_file *m;
    int err;
    struct seq_operations *ops = kmalloc(sizeof(*ops), GFP_KERNEL);
    if (!ops)
        return -ENOMEM;
    ops->start = single_start;
    ops->next = single_next;
    ops->show = show;
    ops->stop = single_stop;

    err = seq_open(filp, ops);
    if (err)
    {
        kfree(ops);
        return err;
    }

    m = filp->private_data;
    m->private = data;
    return 0;
}

void single_release(struct file *filp)
{
    struct seq_operations *ops = ((struct seq_file *) filp->private_data)->private;
    seq_release(filp);
    kfree(ops);
}

static __init void seq_file_init()
{
    seq_file_cache = kmem_cache_create("seq_file", sizeof(struct seq_file),
                                       _Alignof(struct seq_file), KMEM_CACHE_PANIC, NULL);
}
