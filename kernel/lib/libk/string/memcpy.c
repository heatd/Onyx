/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <string.h>

#include <onyx/compiler.h>

void *__memcpy(void *__restrict__ dstptr, const void *__restrict__ srcptr, size_t size)
{
    char *__restrict__ d = dstptr;
    const char *__restrict__ s = srcptr;

    for (size_t i = 0; i < size; i++)
    {
        *d++ = *s++;
    }

    return dstptr;
}

weak_alias(__memcpy, memcpy);

void *__memmove(void *dstptr, const void *srcptr, size_t size)
{
    unsigned char *dst = (unsigned char *) dstptr;
    const unsigned char *src = (const unsigned char *) srcptr;
    size_t i;
    if (dst < src)
    {
        for (i = 0; i < size; i++)
            dst[i] = src[i];
    }
    else
    {
        for (i = size; i != 0; i--)
            dst[i - 1] = src[i - 1];
    }

    return dstptr;
}

weak_alias(__memmove, memmove);
