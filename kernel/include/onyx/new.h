/*
 * Copyright (c) 2019 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_NEW_H
#define _ONYX_NEW_H

#include <stddef.h>

inline void *operator new(size_t s, void *ptr)
{
    return ptr;
}

inline void *operator new[](size_t s, void *ptr)
{
    return ptr;
}

inline void operator delete(void *, void *)
{
}
inline void operator delete[](void *, void *)
{
}

#endif
