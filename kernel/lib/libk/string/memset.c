/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stdint.h>
#include <string.h>

#define weak_alias(name, aliasname) _weak_alias(name, aliasname)
#define _weak_alias(name, aliasname) \
    extern __typeof(name) aliasname __attribute__((weak, alias(#name)));

void *__memset(void *bufptr, int value, size_t size)
{
    unsigned char *b = bufptr;
    for (size_t s = 0; s < size; s++)
        *b++ = value;
    return bufptr;
}

weak_alias(__memset, memset);
