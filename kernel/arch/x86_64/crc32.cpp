/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>

typedef uint32_t __attribute__((may_alias)) may_alias_uint32_t;
typedef uint64_t __attribute__((may_alias)) may_alias_uint64_t;
typedef uint16_t __attribute__((may_alias)) may_alias_uint16_t;
typedef uint8_t __attribute__((may_alias)) may_alias_uint8_t;

#define IS_BUFFER_ALIGNED_TO(buf, boundary) (((unsigned long) (buf)) & (boundary))

#define __crc32b(crc, val) __asm__("crc32b %1, %k0" : "+r"(crc) : "r"(val))
#define __crc32w(crc, val) __asm__("crc32w %1, %k0" : "+r"(crc) : "r"(val))
#define __crc32l(crc, val) __asm__("crc32l %1, %k0" : "+r"(crc) : "r"(val))
#define __crc32q(crc, val) __asm__("crc32q %1, %q0" : "+r"(crc) : "r"(val))

uint32_t crc32c_calculate_sse(const void *buffer, size_t length, uint32_t initial_value)
{
    const uint8_t *buf;
    uint64_t Crc;

    buf = (const uint8_t *) buffer;
    Crc = ~initial_value;

    if (length == 0) [[unlikely]]
        return 0;

    /* Step 0: Align the buffer to a word boundary(at least).*/
    if (IS_BUFFER_ALIGNED_TO(buf, 1))
    {
        __crc32b(Crc, *buf);
        buf++;
        length--;
    }

    /* Right now, nr_blocks represents the number of 16-bit blocks */
    auto nr_blocks = length >> 1;

    if (nr_blocks) [[likely]]
    {
        /* Step 1: Align to a dword boundary if we're not already */
        if (IS_BUFFER_ALIGNED_TO(buf, 2))
        {
            __crc32w(Crc, *(may_alias_uint16_t *) buf);
            buf += 2;
            length -= 2;
            nr_blocks--;
        }

        /* Now, we switched to a block_size of 32 bits(4 bytes) */
        nr_blocks >>= 1;

        if (nr_blocks)
        {
            if (IS_BUFFER_ALIGNED_TO(buf, 4))
            {
                __crc32l(Crc, *(may_alias_uint32_t *) buf);
                buf += 4;
                length -= 4;
                nr_blocks--;
            }

            /* We're certainly 8-byte aligned right now, so we're going to
             * switch the block size to 64 bytes and enter the main loop.
             */

            /* Note that we save the number of 8 byte blocks for later */
            auto nr_8b_blocks = nr_blocks >> 1;
            nr_blocks >>= 4;

            while (nr_blocks)
            {
                __crc32q(Crc, *(may_alias_uint64_t *) buf);
                __crc32q(Crc, *((may_alias_uint64_t *) buf + 1));
                __crc32q(Crc, *((may_alias_uint64_t *) buf + 2));
                __crc32q(Crc, *((may_alias_uint64_t *) buf + 3));
                __crc32q(Crc, *((may_alias_uint64_t *) buf + 4));
                __crc32q(Crc, *((may_alias_uint64_t *) buf + 5));
                __crc32q(Crc, *((may_alias_uint64_t *) buf + 6));
                __crc32q(Crc, *((may_alias_uint64_t *) buf + 7));
                buf += 64;
                nr_blocks--;
            }

            /* Handle leftover 8-byte blocks */
            nr_8b_blocks %= 8;
            while (nr_8b_blocks)
            {
                __crc32q(Crc, *(may_alias_uint64_t *) buf);
                nr_8b_blocks--;
                buf += 8;
            }

            /* Now we're going to start wrapping up. */
            if (length & 4)
            {
                __crc32l(Crc, *(may_alias_uint32_t *) buf);
                buf += 4;
            }
        }

        if (length & 2)
        {
            __crc32w(Crc, *(may_alias_uint16_t *) buf);
            buf += 2;
        }
    }

    if (length & 1)
        __crc32b(Crc, *(may_alias_uint8_t *) buf);

    return (uint32_t) ~Crc;
}
