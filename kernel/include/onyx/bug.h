/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_BUG_H
#define _ONYX_BUG_H

#include <stdbool.h>

#include <onyx/compiler.h>

#ifdef __x86_64__
#include <platform/bug.h>
#define ARCH_SUPPORTS_BUGON
#endif

__BEGIN_CDECLS

#ifndef ARCH_SUPPORTS_BUGON

void generic_warn(const char *filename, int line);

#define __WARN() generic_warn(__FILE__, __LINE__)

#endif

#define WARN_ON(cond)          \
    ({                         \
        int __cond = !!(cond); \
        if (unlikely(__cond))  \
            __WARN();          \
        unlikely(__cond);      \
    })

#define WARN_ON_ONCE(cond)                                                           \
    ({                                                                               \
        static int do_once = 0;                                                      \
        int __cond = !!(cond);                                                       \
        if (unlikely(__cond && !__atomic_exchange_n(&do_once, 1, __ATOMIC_RELAXED))) \
            __WARN();                                                                \
        unlikely(__cond);                                                            \
    })

__END_CDECLS

#endif
