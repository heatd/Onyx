/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#include <stdio.h>

#include <linux/errno.h>
#include <linux/seq_buf.h>
#include <linux/string.h>

int seq_buf_write(struct seq_buf *m, const void *data, size_t len)
{
    if (m->count + len < m->size)
    {
        memcpy(m->buf + m->count, data, len);
        m->count += len;
        return 0;
    }

    seq_set_overflow(m);
    return -EOVERFLOW;
}

int seq_buf_printf(struct seq_buf *m, const char *s, ...)
{
    int written;
    va_list va;

    if (seq_buf_has_overflowed(m))
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
