/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <string.h>
/* Concatenate the NULL-terminated string src onto the end of dest, and return dest. */
char *strcat(char *restrict dest, const char *restrict src)
{
    char *ret = dest;

    while (*dest != '\0')
        dest++;
    while (*src != '\0')
        *dest++ = *src++;

    *dest = '\0';

    return ret;
}

char *strncat(char *restrict dest, const char *restrict src, size_t n)
{
    char *ret = dest;
    size_t dst_len = strlen(dest);

    dest += dst_len;

    while (*src != '\0' && n-- != 0)
        *dest++ = *src++;

    *dest = '\0';

    return ret;
}
