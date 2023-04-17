/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_SELECT_H
#define _UAPI_SELECT_H

#define FD_SETSIZE 1024

typedef unsigned long fd_mask;

typedef struct
{
    unsigned long fds_bits[FD_SETSIZE / 8 / sizeof(long)];
} fd_set;

#define FD_ZERO(s)                                            \
    do                                                        \
    {                                                         \
        int __i;                                              \
        unsigned long *__b = (s)->fds_bits;                   \
        for (__i = sizeof(fd_set) / sizeof(long); __i; __i--) \
            *__b++ = 0;                                       \
    } while (0)
#define FD_SET(d, s) \
    ((s)->fds_bits[(d) / (8 * sizeof(long))] |= (1UL << ((d) % (8 * sizeof(long)))))
#define FD_CLR(d, s) \
    ((s)->fds_bits[(d) / (8 * sizeof(long))] &= ~(1UL << ((d) % (8 * sizeof(long)))))
#define FD_ISSET(d, s) \
    !!((s)->fds_bits[(d) / (8 * sizeof(long))] & (1UL << ((d) % (8 * sizeof(long)))))

#endif
