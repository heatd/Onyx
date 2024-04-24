/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef DO_STREAMS
struct stream
{
    int (*out)(const char *c, int len, struct stream *);
    void (*start)(struct stream *);
    void (*end)(struct stream *);
};
#else
#define stream bufstream
#endif

struct bufstream
{
#ifdef DO_STREAMS
    struct stream stream;
#endif
    char *str;
    size_t n;
};

static int buf_put(const char *str, int len, struct stream *stream)
{
    struct bufstream *bufstr = (struct bufstream *) stream;
    size_t towrite;
    unsigned int may_use = bufstr->n - 1;

    if (!may_use)
        return len;

    towrite = may_use > (unsigned int) len ? (unsigned int) len : may_use;
    memcpy(bufstr->str, str, towrite);
    bufstr->n -= towrite;
    bufstr->str += towrite;
    return len;
}

static void bufstream_end(struct stream *stream)
{
    struct bufstream *bufstr = (struct bufstream *) stream;
    if (bufstr->n < 1)
        __builtin_abort();
    *bufstr->str = '\0';
}

enum integer_type
{
    ITYPE_INVAL = 0,
    ITYPE_HH,
    ITYPE_H,
    ITYPE_INT,
    ITYPE_L,
    ITYPE_LL,
    ITYPE_STR,
    ITYPE_CHAR,
};

#define F_PALT      1
#define F_PZERO     2
#define F_PLEFT     4
#define F_PBLANK    8
#define F_PSIGN     16
#define F_PUNSIGNED 32
#define F_PHEX      64
#define F_PUPPERHEX 128
#define F_POCTAL    256

static const char *digits = "0123456789abcdefghijklmnop";
static const char *DIGITS = "0123456789ABCDEFGHIJKLMNOP";

#define FWIDTH_VARARG    -1
#define PRECISION_VARARG -1
#define PRECISION_UNSPEC -2

struct printf_specifier
{
    int fwidth;
    int precision;
    short flags;
    enum integer_type itype;
};

/* print an int */
static int pint(struct stream *stream, unsigned long val, struct printf_specifier *spec)
{
#define TBUFMAX   30
#define PUTBUF(c) buf[TBUFMAX - 1 - (buflen++)] = c

    char buf[TBUFMAX];
    int buflen = 0;
    const char *d = digits;
    unsigned char base = 10;
    int sign = 0;
    char wazero = 0;
    short flags = spec->flags;
    int precision = spec->precision;
    int fwidth = spec->fwidth;
    int ret = 0;
    char pad;

    if (precision != PRECISION_UNSPEC && fwidth)
    {
        /* If precision & width are specified, we are going to be using blanks and not zeroes */
        flags &= ~F_PZERO;
    }

    pad = flags & F_PZERO ? '0' : ' ';

    if (precision == PRECISION_UNSPEC)
        precision = 1;

    if (flags & (F_PHEX | F_PUPPERHEX))
        base = 16;
    else if (flags & F_POCTAL)
    {
        if (val == 0)
            wazero = 1;
        base = 8;
    }

    if (flags & F_PUPPERHEX)
        d = DIGITS;

    if (!(flags & F_PUNSIGNED))
    {
        if ((long) val < 0)
        {
            val = -val;
            sign = 1;
        }
    }

    while (val)
    {
        unsigned digit = val % base;
        val /= base;

        PUTBUF(d[digit]);
    }

    if (precision < buflen)
        precision = buflen;

    fwidth -= precision;
    if (sign || flags & (F_PSIGN | F_PBLANK))
        fwidth--;
    if (flags & F_PALT)
        fwidth -= flags & F_POCTAL ? 1 : (flags & (F_PHEX | F_PUPPERHEX) ? 2 : 0);

    if (!(flags & (F_PLEFT | F_PZERO)))
    {
        while (fwidth-- > 0)
            buf_put(&pad, 1, stream), ret++;
    }

    if (sign)
    {
        buf_put("-", 1, stream);
        ret++;
    }
    else
    {
        if (flags & F_PSIGN)
            buf_put("+", 1, stream), ret++;
        else if (flags & F_PBLANK)
            buf_put(" ", 1, stream), ret++;
    }

    if (flags & F_PALT && !wazero)
    {
        if (flags & (F_PHEX | F_PUPPERHEX))
        {
            buf_put(flags & F_PUPPERHEX ? "0X" : "0x", 2, stream);
            ret += 2;
        }

        else if (flags & F_POCTAL)
        {
            buf_put("0", 1, stream);
            ret++;
        }
    }

    if (!(flags & F_PLEFT) && flags & F_PZERO)
        while (fwidth-- > 0)
            buf_put(&pad, 1, stream), ret++;

    /* Handle precision */
    while (precision > buflen)
        buf_put("0", 1, stream), precision--, ret++;

    buf_put(buf + TBUFMAX - buflen, buflen, stream);
    ret += buflen;

    /* Finally do some more padding */
    while (fwidth-- > 0)
        buf_put(&pad, 1, stream), ret++;
    return ret;
}
#undef PUTBUF
#undef TBUFMAX

static int process_format(const char *str, struct printf_specifier *spec)
{
    char c;
    const char *s = str;
    int negative = 0;

    /* General format: %[$][flags][width][.precision][length modifier]conversion
     * We're ignoring $ and %n. */

    /* Process flags */
    while ((c = *s))
    {
        switch (c)
        {
            case '0':
                spec->flags |= F_PZERO;
                break;
            case ' ':
                spec->flags |= F_PBLANK;
                break;
            case '#':
                spec->flags |= F_PALT;
                break;
            case '+':
                spec->flags |= F_PSIGN;
                break;
            case '-':
                spec->flags |= F_PLEFT;
                break;
            default:
                goto field_width;
        }

        s++;
    }

field_width:
    /* We might have a field width, check for a digit */
    if (*s == '-')
    {
        negative = 1;
        s++;
    }

    if (*s == '*')
        spec->fwidth = FWIDTH_VARARG, s++;
    else
    {
        while (isdigit(*s))
        {
            spec->fwidth *= 10;
            spec->fwidth += *s - '0';
            s++;
        }

        if (negative)
        {
            spec->fwidth = -spec->fwidth;
            spec->flags |= F_PLEFT;
        }
    }

    if (*s == '.')
    {
        /* We have a precision */
        s++;
        negative = 0;
        spec->precision = 0;
        if (*s == '-')
        {
            negative = 1;
            s++;
        }

        if (*s == '*')
            spec->precision = PRECISION_VARARG, s++;
        else
        {
            while (isdigit(*s))
            {
                spec->precision *= 10;
                spec->precision += *s - '0';
                s++;
            }

            if (negative)
                spec->precision = 0;
        }
    }

    spec->itype = ITYPE_INT;

    while (*s)
    {
        switch (*s)
        {
            case 'h':
                spec->itype = spec->itype == ITYPE_H ? ITYPE_HH : ITYPE_H;
                break;
            case 'l':
                spec->itype = spec->itype == ITYPE_L ? ITYPE_LL : ITYPE_L;
                break;
            case 'z':
            case 't':
                spec->itype = ITYPE_L;
                break;
            case 'j':
                spec->itype = ITYPE_LL;
                break;
            case 'u':
                spec->flags |= F_PUNSIGNED;
                goto out;
            case 'x':
                spec->flags |= F_PUNSIGNED | F_PHEX;
                goto out;
            case 'X':
                spec->flags |= F_PUNSIGNED | F_PUPPERHEX;
                goto out;
            case 'o':
                spec->flags |= F_POCTAL | F_PUNSIGNED;
                goto out;
            case 'p':
                /* make %p %#lx */
                spec->flags |= F_PALT | F_PUNSIGNED | F_PHEX;
                spec->itype = ITYPE_L;
                goto out;
            case 'd':
            case 'i':
                goto out;
            case 's':
                spec->itype = ITYPE_STR;
                goto out;
            case 'c':
                spec->itype = ITYPE_CHAR;
                goto out;
            default:;
                printk("%s: Unhandled specifier %%%c!\n", __func__, *s);
                return -1;
        }

        s++;
    }

out:
    s++;
    return s - str;
}

static int printf_do_string(struct stream *stream, const char *s, int fwidth,
                            unsigned int precision, unsigned short flags)
{
    size_t len = strlen(s);
    int to_write = len < precision ? len : precision;
    int ret = to_write;
    fwidth -= to_write;
    if (!(flags & F_PLEFT))
        while (fwidth-- > 0)
            buf_put(" ", 1, stream), ret++;
    buf_put(s, to_write, stream);
    while (fwidth-- > 0)
        buf_put(" ", 1, stream), ret++;
    return ret;
}

static int __vfprintf(struct stream *stream, const char *s, va_list va)
{
    unsigned long val = 0;
    char c;
    int ret = 0;
    struct printf_specifier spec = {};

#if DO_STREAMS
    if (stream->start)
        stream->start(stream);
#endif

    while ((c = *s))
    {
        char *last;
        int slen = INT_MAX;
        int st = 0;

        if (c == '%')
            goto perc;
        /* Print as long of a !% char run as we can, at once */
        last = strchr(s, '%');
        if (last)
            slen = last - s;

        st = printf_do_string(stream, s, 0, slen, 0);
        if (st < 0)
        {
            ret = st;
            goto out;
        }

        s += st;
        ret += st;
        continue;
    perc:
        s++;
        spec.flags = 0;
        spec.fwidth = 0;
        spec.precision = PRECISION_UNSPEC;
        spec.itype = ITYPE_INVAL;

        if (*s == '%')
        {
            /* Print a single '%' */
            s++;
            c = '%';
            goto print_char;
        }

        st = process_format(s, &spec);
        if (st < 0)
        {
            ret = st;
            goto out;
        }

        s += st;

        if (spec.fwidth == FWIDTH_VARARG)
        {
            spec.fwidth = va_arg(va, int);
            if (spec.fwidth < 0)
            {
                spec.fwidth = -spec.fwidth;
                spec.flags |= F_PLEFT;
            }
        }

        /* '0' and '-' are incompatible */
        if (spec.flags & F_PLEFT)
            spec.flags &= ~F_PZERO;

        if (spec.precision == PRECISION_VARARG)
            spec.precision = va_arg(va, int);

        switch (spec.itype)
        {
            case ITYPE_HH:
                if (spec.flags & F_PUNSIGNED)
                    val = (unsigned char) va_arg(va, unsigned int);
                else
                    val = (signed char) va_arg(va, int);
                goto print_int;
            case ITYPE_H:
                if (spec.flags & F_PUNSIGNED)
                    val = (unsigned short) va_arg(va, unsigned int);
                else
                    val = (short) va_arg(va, int);
                goto print_int;
            case ITYPE_INT:
                if (spec.flags & F_PUNSIGNED)
                    val = va_arg(va, unsigned int);
                else
                    val = va_arg(va, int);
                goto print_int;
            case ITYPE_L:
                if (spec.flags & F_PUNSIGNED)
                    val = va_arg(va, unsigned long);
                else
                    val = va_arg(va, long);
                goto print_int;
            case ITYPE_LL:
                if (spec.flags & F_PUNSIGNED)
                    val = va_arg(va, unsigned long long);
                else
                    val = va_arg(va, long long);
                goto print_int;
            case ITYPE_STR:
                goto print_str;
            case ITYPE_CHAR:
                c = va_arg(va, int);
                goto print_char;
            default:
                __builtin_abort();
        }

    print_int:
        st = pint(stream, val, &spec);
        if (st < 0)
        {
            ret = st;
            goto out;
        }

        ret += st;
        continue;
    print_str:
        st = printf_do_string(stream, va_arg(va, const char *), spec.fwidth, spec.precision,
                              spec.flags);
        if (st < 0)
        {
            ret = st;
            goto out;
        }

        ret += st;
        continue;
    print_char:
        st = printf_do_string(stream, &c, spec.fwidth, 1, spec.flags);
        if (st < 0)
        {
            ret = st;
            goto out;
        }

        ret += st;
    }
out:
#ifdef DO_STREAMS
    if (stream->end)
        stream->end(stream);
#else
    bufstream_end(stream);
#endif
    return ret;
}

static void bufstream_init(struct bufstream *bufstr, char *buf, size_t n)
{
    bufstr->str = buf;
    bufstr->n = n;
#ifdef DO_STREAMS
    bufstr->stream.out = buf_put;
    bufstr->stream.start = NULL;
    bufstr->stream.end = bufstream_end;
#endif
}

int vsnprintf(char *str, size_t n, const char *fmt, va_list ap)
{
    struct bufstream bufstr;
    bufstream_init(&bufstr, str, n);
    return __vfprintf((struct stream *) &bufstr, fmt, ap);
}

int snprintf(char *str, size_t n, const char *fmt, ...)
{
    int ret;
    va_list list;
    va_start(list, fmt);
    ret = vsnprintf(str, n, fmt, list);
    va_end(list);

    return ret;
}

int sprintf(char *str, const char *fmt, ...)
{
    int ret;
    va_list list;
    va_start(list, fmt);
    ret = vsnprintf(str, INT_MAX, fmt, list);
    va_end(list);
    return ret;
}
