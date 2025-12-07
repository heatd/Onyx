#ifndef _LINUX_SEQ_BUF_H
#define _LINUX_SEQ_BUF_H

#include <stddef.h>

#include <linux/types.h>
#include <linux/seq_file.h>
#include <linux/string_helpers.h>

struct seq_buf
{
    char *buf;
    size_t size;
    size_t count;
};

#define DECLARE_SEQ_BUF(name, size_)    \
	struct seq_buf name = {             \
		.buf = (char[size_]) {0},       \
		.size = (size_),                \
	}

static void seq_set_overflow(struct seq_buf *m)
{
    m->count = m->size + 1;
}

static bool seq_buf_has_overflowed(struct seq_buf *m)
{
    return m->count == m->size + 1;
}

int seq_buf_write(struct seq_buf *m, const void *data, size_t len);
int seq_buf_printf(struct seq_buf *m, const char *format, ...);

static inline const char *seq_buf_str(struct seq_buf *m)
{
    /* Null terminate it at the end, or truncate it. */
    if (m->count < m->size)
        m->buf[m->count] = '\0';
    else
        m->buf[m->size - 1] = '\0';
    return m->buf;
}

#endif
