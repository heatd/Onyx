/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_FNV_H
#define _KERNEL_FNV_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/utils.h>

typedef uint32_t fnv_hash_t;

#define FNV_PRIME        16777619
#define FNV_OFFSET_BASIS 2166136261

CONSTEXPR static inline fnv_hash_t __fnv_hash(const uint8_t *data, size_t size)
{
    fnv_hash_t hash = FNV_OFFSET_BASIS;
    while (size--)
    {
        hash *= FNV_PRIME;
        hash ^= *data++;
    }

    return hash;
}

/* Used when continuing hashes (you'd call fnv_hash() and then call fnv_hash_cont
 * with the old hash as to continue hashing)
 */
CONSTEXPR static inline fnv_hash_t __fnv_hash_cont(const uint8_t *data, size_t size,
                                                   fnv_hash_t hash)
{
    while (size--)
    {
        hash *= FNV_PRIME;
        hash ^= *data++;
    }

    return hash;
}

#define fnv_hash(data, size)            __fnv_hash((const uint8_t *)data, size)
#define fnv_hash_cont(data, size, hash) __fnv_hash_cont((const uint8_t *)data, size, hash)

#endif
