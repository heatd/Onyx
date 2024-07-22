/*
 * Copyright (c) 2016-2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <string.h>
/* Copy the NULL-terminated string src into dest, and return dest. */
char *strcpy(char *dest, const char *src)
{
    char *ret = dest;
    while (*src != '\0')
        *dest++ = *src++;
    *dest = '\0';
    return ret;
}

char *strncpy(char *dest, const char *src, size_t count)
{
    char *ret = dest;
    while (count--)
    {
        if (*src != '\0')
            *dest++ = *src++;
        else
            *dest++ = '\0';
    }

    return ret;
}

/* musl-1.16 code */
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#pragma GCC diagnostic ignored "-Wparentheses"

#define ALIGN      (sizeof(size_t) - 1)
#define ONES       ((size_t) -1 / UCHAR_MAX)
#define HIGHS      (ONES * (UCHAR_MAX / 2 + 1))
#define HASZERO(x) ((x) -ONES & ~(x) &HIGHS)

size_t strlcpy(char *d, const char *s, size_t n)
{
    char *d0 = d;
    size_t *wd;
    const size_t *ws;

    if (!n--)
        goto finish;
    if (((uintptr_t) s & ALIGN) == ((uintptr_t) d & ALIGN))
    {
        for (; ((uintptr_t) s & ALIGN) && n && (*d = *s); n--, s++, d++)
            ;
        if (n && *s)
        {
            wd = (void *) d;
            ws = (const void *) s;
            for (; n >= sizeof(size_t) && !HASZERO(*ws); n -= sizeof(size_t), ws++, wd++)
                *wd = *ws;
            d = (void *) wd;
            s = (const void *) ws;
        }
    }
    for (; n && (*d = *s); n--, s++, d++)
        ;
    *d = 0;
finish:
    return d - d0 + strlen(s);
}
