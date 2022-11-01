#define _POSIX_SOURCE
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define NL_ARGMAX 9

#pragma GCC diagnostic ignored "-Wsign-compare"

#ifdef __clang__
#pragma GCC diagnostic ignored "-Wshift-op-parentheses"
#else
// GCC warnings
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#endif

struct sprintf_buf
{
    char *buf;
    size_t pos;
};

int wctomb(char *s, wchar_t wc);

/* Some useful macros */

#define MAX(a, b)     ((a) > (b) ? (a) : (b))
#define MIN(a, b)     ((a) < (b) ? (a) : (b))
#define CONCAT2(x, y) x##y
#define CONCAT(x, y)  CONCAT2(x, y)

/* Convenient bit representation for modifier flags, which all fall
 * within 31 codepoints of the space character. */

#define ALT_FORM (1U << ('#' - ' '))
#define ZERO_PAD (1U << ('0' - ' '))
#define LEFT_ADJ (1U << ('-' - ' '))
#define PAD_POS  (1U << (' ' - ' '))
#define MARK_POS (1U << ('+' - ' '))
#define GROUPED  (1U << ('\'' - ' '))

#define FLAGMASK (ALT_FORM | ZERO_PAD | LEFT_ADJ | PAD_POS | MARK_POS | GROUPED)

#if UINT_MAX == ULONG_MAX
#define LONG_IS_INT
#endif

#if SIZE_MAX != ULONG_MAX || UINTMAX_MAX != ULLONG_MAX
#define ODD_TYPES
#endif

/* State machine to accept length modifiers + conversion specifiers.
 * Result is 0 on failure, or an argument type to pop on success. */

enum
{
    BARE,
    LPRE,
    LLPRE,
    HPRE,
    HHPRE,
    BIGLPRE,
    ZTPRE,
    JPRE,
    STOP,
    PTR,
    INT,
    UINT,
    ULLONG,
#ifndef LONG_IS_INT
    LONG,
    ULONG,
#else
#define LONG  INT
#define ULONG UINT
#endif
    SHORT,
    USHORT,
    CHAR,
    UCHAR,
#ifdef ODD_TYPES
    LLONG,
    SIZET,
    IMAX,
    UMAX,
    PDIFF,
    UIPTR,
#else
#define LLONG ULLONG
#define SIZET ULONG
#define IMAX  LLONG
#define UMAX  ULLONG
#define PDIFF LONG
#define UIPTR ULONG
#endif
    DBL,
    LDBL,
    NOARG,
    MAXSTATE
};

#define S(x) [(x) - 'A']

static const unsigned char states[]['z' - 'A' + 1] = {
    {
        /* 0: bare types */
        S('d') = INT,   S('i') = INT,   S('o') = UINT, S('u') = UINT,    S('x') = UINT,
        S('X') = UINT,  S('e') = DBL,   S('f') = DBL,  S('g') = DBL,     S('a') = DBL,
        S('E') = DBL,   S('F') = DBL,   S('G') = DBL,  S('A') = DBL,     S('c') = CHAR,
        S('C') = INT,   S('s') = PTR,   S('S') = PTR,  S('p') = UIPTR,   S('n') = PTR,
        S('m') = NOARG, S('l') = LPRE,  S('h') = HPRE, S('L') = BIGLPRE, S('z') = ZTPRE,
        S('j') = JPRE,  S('t') = ZTPRE,
    },
    {
        /* 1: l-prefixed */
        S('d') = LONG,
        S('i') = LONG,
        S('o') = ULONG,
        S('u') = ULONG,
        S('x') = ULONG,
        S('X') = ULONG,
        S('e') = DBL,
        S('f') = DBL,
        S('g') = DBL,
        S('a') = DBL,
        S('E') = DBL,
        S('F') = DBL,
        S('G') = DBL,
        S('A') = DBL,
        S('c') = INT,
        S('s') = PTR,
        S('n') = PTR,
        S('l') = LLPRE,
    },
    {
        /* 2: ll-prefixed */
        S('d') = LLONG,
        S('i') = LLONG,
        S('o') = ULLONG,
        S('u') = ULLONG,
        S('x') = ULLONG,
        S('X') = ULLONG,
        S('n') = PTR,
    },
    {
        /* 3: h-prefixed */
        S('d') = SHORT,
        S('i') = SHORT,
        S('o') = USHORT,
        S('u') = USHORT,
        S('x') = USHORT,
        S('X') = USHORT,
        S('n') = PTR,
        S('h') = HHPRE,
    },
    {
        /* 4: hh-prefixed */
        S('d') = CHAR,
        S('i') = CHAR,
        S('o') = UCHAR,
        S('u') = UCHAR,
        S('x') = UCHAR,
        S('X') = UCHAR,
        S('n') = PTR,
    },
    {
        /* 5: L-prefixed */
        S('e') = LDBL,
        S('f') = LDBL,
        S('g') = LDBL,
        S('a') = LDBL,
        S('E') = LDBL,
        S('F') = LDBL,
        S('G') = LDBL,
        S('A') = LDBL,
        S('n') = PTR,
    },
    {
        /* 6: z- or t-prefixed (assumed to be same size) */
        S('d') = PDIFF,
        S('i') = PDIFF,
        S('o') = SIZET,
        S('u') = SIZET,
        S('x') = SIZET,
        S('X') = SIZET,
        S('n') = PTR,
    },
    {
        /* 7: j-prefixed */
        S('d') = IMAX,
        S('i') = IMAX,
        S('o') = UMAX,
        S('u') = UMAX,
        S('x') = UMAX,
        S('X') = UMAX,
        S('n') = PTR,
    }};

#define OOB(x) ((unsigned) (x) - 'A' > 'z' - 'A')

union arg {
    uintmax_t i;
    long double f;
    void *p;
};

static void pop_arg(union arg *arg, int type, va_list *ap)
{
    /* Give the compiler a hint for optimizing the switch. */
    if ((unsigned) type > MAXSTATE)
        return;
    switch (type)
    {
        case PTR:
            arg->p = va_arg(*ap, void *);
            break;
        case INT:
            arg->i = va_arg(*ap, int);
            break;
        case UINT:
            arg->i = va_arg(*ap, unsigned int);
#ifndef LONG_IS_INT
            break;
        case LONG:
            arg->i = va_arg(*ap, long);
            break;
        case ULONG:
            arg->i = va_arg(*ap, unsigned long);
#endif
            break;
        case ULLONG:
            arg->i = va_arg(*ap, unsigned long long);
            break;
        case SHORT:
            arg->i = (short) va_arg(*ap, int);
            break;
        case USHORT:
            arg->i = (unsigned short) va_arg(*ap, int);
            break;
        case CHAR:
            arg->i = (signed char) va_arg(*ap, int);
            break;
        case UCHAR:
            arg->i = (unsigned char) va_arg(*ap, int);
#ifdef ODD_TYPES
            break;
        case LLONG:
            arg->i = va_arg(*ap, long long);
            break;
        case SIZET:
            arg->i = va_arg(*ap, size_t);
            break;
        case IMAX:
            arg->i = va_arg(*ap, intmax_t);
            break;
        case UMAX:
            arg->i = va_arg(*ap, uintmax_t);
            break;
        case PDIFF:
            arg->i = va_arg(*ap, ptrdiff_t);
            break;
        case UIPTR:
            arg->i = (uintptr_t) va_arg(*ap, void *);
#endif
    }
}

static void out(struct sprintf_buf *f, const char *s, size_t l)
{
    memcpy(f->buf + f->pos, s, l);
    f->pos += l;
    f->buf[f->pos] = '\0';
}

static void pad(struct sprintf_buf *f, char c, int w, int l, int fl)
{
    char pad[256];
    if (fl & (LEFT_ADJ | ZERO_PAD) || l >= w)
        return;
    l = w - l;
    memset(pad, c, l > sizeof pad ? sizeof pad : l);
    for (; l >= sizeof pad; l -= sizeof pad)
        out(f, pad, sizeof pad);
    out(f, pad, l);
}

static const char xdigits[16] = {"0123456789ABCDEF"};

static char *fmt_x(uintmax_t x, char *s, int lower)
{
    for (; x; x >>= 4)
        *--s = xdigits[(x & 15)] | lower;
    return s;
}

static char *fmt_o(uintmax_t x, char *s)
{
    for (; x; x >>= 3)
        *--s = '0' + (x & 7);
    return s;
}

static char *fmt_u(uintmax_t x, char *s)
{
    unsigned long y;
    for (; x > ULONG_MAX; x /= 10)
        *--s = '0' + x % 10;
    for (y = x; y; y /= 10)
        *--s = '0' + y % 10;
    return s;
}

static int getint(char **s)
{
    int i;
    for (i = 0; isdigit(**s); (*s)++)
        i = 10 * i + (**s - '0');
    return i;
}

static int printf_core(struct sprintf_buf *f, const char *fmt, va_list *ap, union arg *nl_arg,
                       int *nl_type)
{
    char *a, *z, *s = (char *) fmt;
    unsigned l10n = 0, fl;
    int w, p;
    union arg arg;
    int argpos;
    unsigned st, ps;
    int cnt = 0, l = 0;
    int i;
    char buf[sizeof(uintmax_t) * 3 + 3 + LDBL_MANT_DIG / 4];
    const char *prefix;
    int t, pl;
    wchar_t wc[2], *ws;
    char mb[4];

    for (;;)
    {
        /* Update output count, end loop when fmt is exhausted */
        if (cnt >= 0)
        {
            if (l > INT_MAX - cnt)
            {
                errno = EOVERFLOW;
                cnt = -1;
            }
            else
                cnt += l;
        }
        if (!*s)
            break;

        /* Handle literal text and %% format specifiers */
        for (a = s; *s && *s != '%'; s++)
            ;
        for (z = s; s[0] == '%' && s[1] == '%'; z++, s += 2)
            ;
        l = z - a;
        if (f)
            out(f, a, l);
        if (l)
            continue;

        if (isdigit(s[1]) && s[2] == '$')
        {
            l10n = 1;
            argpos = s[1] - '0';
            s += 3; // bockk
        }
        else
        {
            argpos = -1;
            s++;
        }

        /* Read modifier flags */
        for (fl = 0; (unsigned) *s - ' ' < 32 && (FLAGMASK & (1U << *s - ' ')); s++)
            fl |= 1U << *s - ' ';

        /* Read field width */
        if (*s == '*')
        {
            if (isdigit(s[1]) && s[2] == '$')
            {
                l10n = 1;
                nl_type[s[1] - '0'] = INT;
                w = nl_arg[s[1] - '0'].i;
                s += 3;
            }
            else if (!l10n)
            {
                w = f ? va_arg(*ap, int) : 0;
                s++;
            }
            else
                return -1;
            if (w < 0)
                fl |= LEFT_ADJ, w = -w;
        }
        else if ((w = getint(&s)) < 0)
            return -1;

        /* Read precision */
        if (*s == '.' && s[1] == '*')
        {
            if (isdigit(s[2]) && s[3] == '$')
            {
                nl_type[s[2] - '0'] = INT;
                p = nl_arg[s[2] - '0'].i;
                s += 4;
            }
            else if (!l10n)
            {
                p = f ? va_arg(*ap, int) : 0;
                s += 2;
            }
            else
                return -1;
        }
        else if (*s == '.')
        {
            s++;
            p = getint(&s);
        }
        else
            p = -1;

        /* Format specifier state machine */
        st = 0;
        do
        {
            if (OOB(*s))
                return -1;
            ps = st;
            st = states[st] S(*s++);
        } while (st - 1 < STOP);
        if (!st)
            return -1;

        /* Check validity of argument type (nl/normal) */
        if (st == NOARG)
        {
            if (argpos >= 0)
                return -1;
            else if (!f)
                continue;
        }
        else
        {
            if (argpos >= 0)
                nl_type[argpos] = st, arg = nl_arg[argpos];
            else if (f)
                pop_arg(&arg, st, ap);
            else
                return 0;
        }

        if (!f)
            continue;

        z = buf + sizeof(buf);
        prefix = "-+   0X0x";
        pl = 0;
        t = s[-1];

        /* Transform ls,lc -> S,C */
        if (ps && (t & 15) == 3)
            t &= ~32;

        /* - and 0 flags are mutually exclusive */
        if (fl & LEFT_ADJ)
            fl &= ~ZERO_PAD;

        switch (t)
        {
            case 'n':
                switch (ps)
                {
                    case BARE:
                        *(int *) arg.p = cnt;
                        break;
                    case LPRE:
                        *(long *) arg.p = cnt;
                        break;
                    case LLPRE:
                        *(long long *) arg.p = cnt;
                        break;
                    case HPRE:
                        *(unsigned short *) arg.p = cnt;
                        break;
                    case HHPRE:
                        *(unsigned char *) arg.p = cnt;
                        break;
                    case ZTPRE:
                        *(size_t *) arg.p = cnt;
                        break;
                    case JPRE:
                        *(uintmax_t *) arg.p = cnt;
                        break;
                }
                continue;
            case 'p':
                p = MAX(p, 2 * sizeof(void *));
                t = 'x';
                fl |= ALT_FORM;
            case 'x':
            case 'X':
                a = fmt_x(arg.i, z, t & 32);
                if (arg.i && (fl & ALT_FORM))
                    prefix += (t >> 4), pl = 2;
                if (0)
                {
                    case 'o':
                        a = fmt_o(arg.i, z);
                        if ((fl & ALT_FORM) && arg.i)
                            prefix += 5, pl = 1;
                }
                if (0)
                {
                    case 'd':
                    case 'i':
                        pl = 1;
                        if (arg.i > INTMAX_MAX)
                        {
                            arg.i = -arg.i;
                        }
                        else if (fl & MARK_POS)
                        {
                            prefix++;
                        }
                        else if (fl & PAD_POS)
                        {
                            prefix += 2;
                        }
                        else
                            pl = 0;
                    case 'u':
                        a = fmt_u(arg.i, z);
                }
                if (p >= 0)
                    fl &= ~ZERO_PAD;
                if (!arg.i && !p)
                {
                    a = z;
                    break;
                }
                p = MAX(p, z - a + !arg.i);
                break;
            case 'c':
                *(a = z - (p = 1)) = arg.i;
                fl &= ~ZERO_PAD;
                break;
            case 'm':
                if (1)
                    a = strerror(errno);
                else
                case 's':
                    a = arg.p ? arg.p : "(null)";
                z = memchr(a, 0, p);
                if (!z)
                    z = a + p;
                else
                    p = z - a;
                fl &= ~ZERO_PAD;
                break;
            case 'C':
                wc[0] = arg.i;
                wc[1] = 0;
                arg.p = wc;
                p = -1;
            case 'S':
                ws = arg.p;
                for (i = l = 0;
                     i < 0U + p && *ws && (l = wctomb(mb, *ws++)) >= 0 && l <= 0U + p - i; i += l)
                    ;
                if (l < 0)
                    return -1;
                p = i;
                pad(f, ' ', w, p, fl);
                ws = arg.p;
                for (i = 0; i < 0U + p && *ws && i + (l = wctomb(mb, *ws++)) <= p; i += l)
                    out(f, mb, l);
                pad(f, ' ', w, p, fl ^ LEFT_ADJ);
                l = w > p ? w : p;
                continue;
        }

        if (p < z - a)
            p = z - a;
        if (w < pl + p)
            w = pl + p;

        pad(f, ' ', w, pl + p, fl);
        out(f, prefix, pl);
        pad(f, '0', w, pl + p, fl ^ ZERO_PAD);
        pad(f, '0', p, z - a, 0);
        out(f, a, z - a);
        pad(f, ' ', w, pl + p, fl ^ LEFT_ADJ);

        l = w;
    }

    if (f)
        return cnt;
    if (!l10n)
        return 0;

    for (i = 1; i <= NL_ARGMAX && nl_type[i]; i++)
        pop_arg(nl_arg + i, nl_type[i], ap);
    for (; i <= NL_ARGMAX && !nl_type[i]; i++)
        ;
    if (i <= NL_ARGMAX)
        return -1;
    return 1;
}

int vsprintf(char *f, const char *fmt, va_list ap)
{
    va_list ap2;
    int nl_type[NL_ARGMAX + 1] = {0};
    union arg nl_arg[NL_ARGMAX + 1];
    int ret;

    struct sprintf_buf buf;
    buf.buf = f;
    buf.pos = 0;

    va_copy(ap2, ap);
    if ((ret = printf_core(&buf, fmt, &ap2, nl_arg, nl_type)) < 0)
        return -1;
    return ret;
}

int sprintf(char *f, const char *fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vsprintf(f, fmt, ap);
    va_end(ap);
    return ret;
}

size_t wcrtomb(char *restrict s, wchar_t wc, mbstate_t *restrict st)
{
    if (!s)
        return 1;
    if ((unsigned) wc < 0x80)
    {
        *s = wc;
        return 1;
    }
    else if ((unsigned) wc < 0x800)
    {
        *s++ = 0xc0 | (wc >> 6);
        *s = 0x80 | (wc & 0x3f);
        return 2;
    }
    else if ((unsigned) wc < 0xd800 || (unsigned) wc - 0xe000 < 0x2000)
    {
        *s++ = 0xe0 | (wc >> 12);
        *s++ = 0x80 | ((wc >> 6) & 0x3f);
        *s = 0x80 | (wc & 0x3f);
        return 3;
    }
    else if ((unsigned) wc - 0x10000 < 0x100000)
    {
        *s++ = 0xf0 | (wc >> 18);
        *s++ = 0x80 | ((wc >> 12) & 0x3f);
        *s++ = 0x80 | ((wc >> 6) & 0x3f);
        *s = 0x80 | (wc & 0x3f);
        return 4;
    }
    errno = EILSEQ;
    return -1;
}

int wctomb(char *s, wchar_t wc)
{
    if (!s)
        return 0;
    return wcrtomb(s, wc, 0);
}

int vsnprintf(char *restrict s, size_t n, const char *restrict fmt, va_list ap)
{
    return vsprintf(s, fmt, ap);
}

int snprintf(char *restrict s, size_t n, const char *restrict fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    int ret = vsnprintf(s, n, fmt, va);
    va_end(va);

    return ret;
}
