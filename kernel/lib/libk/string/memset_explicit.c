/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>

void *memset_explicit(void *s, int c, size_t n)
{
    void *dest = memset(s, c, n);
    __asm__ __volatile__("" ::"r"(dest) : "memory");
    return dest;
}
