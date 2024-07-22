/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <string.h>

char *strchr(const char *str, int c)
{
    char *s = (char *) str;
    for (;; s++)
    {
        if (*s == c)
            return s;

        if (*s == '\0')
            return NULL;
    }
}

char *strrchr(const char *str, int c)
{
    char *s = (char *) str;
    char *last = NULL;

    for (;; s++)
    {
        if (*s == c)
            last = s;

        if (*s == '\0')
            return last;
    }
}

char *strnchr(const char *str, size_t len, int c)
{
    char *s = (char *) str;
    for (; len > 0; s++, len--)
    {
        if (*s == c)
            return s;

        if (*s == '\0')
            break;
    }

    return NULL;
}
