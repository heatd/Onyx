/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <string.h>
#include <wchar.h>
wchar_t *wmemcpy(wchar_t *restrict ws1, const wchar_t *restrict ws2, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        ws1[i] = ws2[i];
    }
    return ws1;
}