/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

char *stpcpy(char *restrict s1, const char *restrict s2)
{
    char *restrict dst = s1;
    const char *restrict src = s2;
    do
    {
        *dst++ = *src++;
    } while (*src != '\0');

    return dst - 1;
}
