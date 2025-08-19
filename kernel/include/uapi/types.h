/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_TYPES_H
#define _UAPI_TYPES_H

#ifdef __is_onyx_kernel
#include <onyx/types.h>
#else
/* Assume standard LP64-ish types - char = 1 byte, short = 2, int = 4,
   long long = 8, long = native word.
 */
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef unsigned long __uptr;
typedef unsigned long __usize;
#endif
#endif
