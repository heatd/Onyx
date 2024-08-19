/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_UTILS_H
#define _ONYX_UTILS_H

#include <stdbool.h>
#include <stddef.h>

#include <onyx/compiler.h>

__BEGIN_CDECLS

void *memdup(const void *ptr, size_t size);
void *copy_page(void *vaddr, void *p2);
void *copy_page_to_page(void *p1, void *p2);

__END_CDECLS

#define container_of(ptr, type, member) ((type *) ((char *) ptr - offsetof(type, member)))
#define containerof_null_safe(ptr, type, member) \
    ((ptr) == NULL ? NULL : container_of(ptr, type, member))
#ifndef __cplusplus
#define min(x, y)              \
    ({                         \
        __auto_type __x = x;   \
        __auto_type __y = y;   \
        __x < __y ? __x : __y; \
    })

#define max(x, y)              \
    ({                         \
        __auto_type __x = x;   \
        __auto_type __y = y;   \
        __x > __y ? __x : __y; \
    })

#define align_up2(number, alignment) (((number) + ((alignment) -1)) & -(alignment))
#else

template <typename Type>
Type min(Type t1, Type t2)
{
    return t1 < t2 ? t1 : t2;
}

#endif

static inline bool array_overflows(size_t n, size_t elem_size)
{
    return n > (size_t) -1 / elem_size;
}

#ifdef __cplusplus
/* Handy define for functions that can totally be constexpr in C++ */
#define CONSTEXPR constexpr

template <typename Type>
static inline bool array_overflows(size_t n)
{
    return array_overflows(n, sizeof(Type));
}

#else

#define CONSTEXPR

#endif

#define __stringify(str) #str
#define stringify(str)   __stringify(str)

#ifdef __cplusplus
/**
 * @brief Check if two (numeric, pointer, ...) ranges overlap.
 * These ranges are treated as X = [x1, x2] and Y = [y1, y2]
 *
 * @tparam Type Type of the variables to be compared
 * @param x1 Lower boundary of X
 * @param x2 Upper boundary of X
 * @param y1 Lower boundary of Y
 * @param y2 Upper boundary of Y
 * @return True if they overlap, else false
 */
template <typename Type>
static inline constexpr bool check_for_overlap(Type x1, Type x2, Type y1, Type y2)
{
    return x1 <= y2 && y1 <= x2;
}

#endif

#endif
