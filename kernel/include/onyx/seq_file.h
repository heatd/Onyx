/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_SEQ_FILE_H
#define _ONYX_SEQ_FILE_H

#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/mutex.h>

struct seq_file;
struct file;
struct iovec_iter;
struct path;

__BEGIN_CDECLS

struct seq_operations
{
    void *(*start)(struct seq_file *m, off_t *pos);
    void (*stop)(struct seq_file *m, void *v);
    void *(*next)(struct seq_file *m, void *v, off_t *pos);
    int (*show)(struct seq_file *m, void *v);
};

struct seq_file
{
    char *buf;
    size_t from;
    size_t count;
    size_t size;
    off_t index;
    struct mutex lock;
    const struct file *file;
#ifdef __cplusplus
    void *private_;
#else
    void *private;
#endif
    const struct seq_operations *op;
};

#define SEQ_START_TOKEN ((void *) 1)
#define SEQ_SKIP        1

static inline bool seq_has_overflowed(struct seq_file *m)
{
    return m->count == m->size;
}

int seq_open(struct file *, const struct seq_operations *);
ssize_t seq_read_iter(struct file *filp, size_t off, struct iovec_iter *iter, unsigned int flags);
off_t seq_lseek(struct file *, off_t, int);
void seq_release(struct file *);

int seq_putc(struct seq_file *m, char c);
int seq_puts(struct seq_file *m, const char *s);
__attribute__((format(printf, 2, 3))) int seq_printf(struct seq_file *m, const char *s, ...);

struct list_head *seq_list_start(struct list_head *head, off_t pos);
struct list_head *seq_list_start_head(struct list_head *head, off_t pos);
struct list_head *seq_list_next(void *v, struct list_head *head, off_t *ppos);
struct list_head *seq_list_start_rcu(struct list_head *head, off_t pos);
struct list_head *seq_list_start_head_rcu(struct list_head *head, off_t pos);
struct list_head *seq_list_next_rcu(void *v, struct list_head *head, off_t *ppos);

int seq_d_path_under_root(struct seq_file *m, const struct path *path, const struct path *root);

int single_open(struct file *filp, int (*show)(struct seq_file *, void *), void *data);
void single_release(struct file *filp);

__END_CDECLS
#endif
