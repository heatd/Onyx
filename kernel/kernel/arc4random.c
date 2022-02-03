/*	$OpenBSD: arc4random.c,v 1.48 2014/07/19 00:08:41 deraadt Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $OpenBSD: chacha_private.h,v 1.2 2013/10/04 07:02:27 djm Exp $ */

/* Based on:
 * chacha-merged.c version 20080118
 * D. J. Bernstein
 * Public domain.
 */

/* Adapted for Onyx */

#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <onyx/random.h>
#include <onyx/spinlock.h>

void explicit_bzero(void* ptr, size_t size)
{
    memset(ptr, 0, size);
    __asm__ __volatile__("" ::: "memory");
}

struct chacha
{
    uint32_t input[16];
};

static inline uint32_t chacha_read_little_uint32(const unsigned char* buf)
{
    return (uint32_t) buf[0] << 0 | (uint32_t) buf[1] << 8 | (uint32_t) buf[2] << 16 |
           (uint32_t) buf[3] << 24;
}

static void chacha_keysetup(struct chacha* ctx, const unsigned char* key)
{
    const unsigned char* sigma = (const unsigned char*) "expand 32-byte k";

    ctx->input[0] = chacha_read_little_uint32(sigma + 0 * sizeof(uint32_t));
    ctx->input[1] = chacha_read_little_uint32(sigma + 1 * sizeof(uint32_t));
    ctx->input[2] = chacha_read_little_uint32(sigma + 2 * sizeof(uint32_t));
    ctx->input[3] = chacha_read_little_uint32(sigma + 3 * sizeof(uint32_t));
    ctx->input[4] = chacha_read_little_uint32(key + 0 * sizeof(uint32_t));
    ctx->input[5] = chacha_read_little_uint32(key + 1 * sizeof(uint32_t));
    ctx->input[6] = chacha_read_little_uint32(key + 2 * sizeof(uint32_t));
    ctx->input[7] = chacha_read_little_uint32(key + 3 * sizeof(uint32_t));
    ctx->input[8] = chacha_read_little_uint32(key + 4 * sizeof(uint32_t));
    ctx->input[9] = chacha_read_little_uint32(key + 5 * sizeof(uint32_t));
    ctx->input[10] = chacha_read_little_uint32(key + 6 * sizeof(uint32_t));
    ctx->input[11] = chacha_read_little_uint32(key + 7 * sizeof(uint32_t));
}

static void chacha_ivsetup(struct chacha* ctx, const unsigned char* iv)
{
    ctx->input[12] = 0;
    ctx->input[13] = 0;
    ctx->input[14] = chacha_read_little_uint32(iv + 0 * sizeof(uint32_t));
    ctx->input[15] = chacha_read_little_uint32(iv + 1 * sizeof(uint32_t));
}

static inline uint32_t chacha_rotate(uint32_t v, uint32_t n)
{
    return (v << n) | (v >> (32 - n));
}

static inline void chacha_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d)
{
    *a = *a + *b;
    *d = chacha_rotate(*d ^ *a, 16);
    *c = *c + *d;
    *b = chacha_rotate(*b ^ *c, 12);
    *a = *a + *b;
    *d = chacha_rotate(*d ^ *a, 8);
    *c = *c + *d;
    *b = chacha_rotate(*b ^ *c, 7);
}

static void chacha_keystream(struct chacha* ctx, unsigned char* keystream, size_t size)
{
    uint32_t work[16];

    for (size_t offset = 0; offset < size;)
    {
        size_t left = size - offset;

        for (size_t i = 0; i < 16; i++)
            work[i] = ctx->input[i];

        /* NOTE: This is 20 in the OpenBSD version, but 8 in Bernstein's. */
        /* TODO: Why decrement by 2 instead of 1? */
        for (int i = 20; 0 < i; i -= 2)
        {
            chacha_quarter_round(&work[0], &work[4], &work[8], &work[12]);
            chacha_quarter_round(&work[1], &work[5], &work[9], &work[13]);
            chacha_quarter_round(&work[2], &work[6], &work[10], &work[14]);
            chacha_quarter_round(&work[3], &work[7], &work[11], &work[15]);
            chacha_quarter_round(&work[0], &work[5], &work[10], &work[15]);
            chacha_quarter_round(&work[1], &work[6], &work[11], &work[12]);
            chacha_quarter_round(&work[2], &work[7], &work[8], &work[13]);
            chacha_quarter_round(&work[3], &work[4], &work[9], &work[14]);
        }

        for (size_t i = 0; i < 16; i++)
            work[i] += ctx->input[i];

        ctx->input[12] += 1;
        if (ctx->input[12] == 0)
        {
            ctx->input[13] += 1;
            /* Stopping at 2^70 bytes per nonce is user's responsibility. */
        }

        for (size_t i = 0; i < 16; i++)
            work[i] = htole32(work[i]);

        size_t amount = left < 64 ? left : 64;
        memcpy(keystream + offset, work, amount);
        offset += amount;
    }

    explicit_bzero(work, sizeof(work));
}

#define KEYSZ 32
#define IVSZ  8

static bool rs_initialized = false;
static size_t rs_have = 0;
static size_t rs_count = 0;
static struct chacha rs_chacha;
static unsigned char rs_buf[16 * 64];
static struct spinlock random_lock;

void arc4random_buf(void* buffer_ptr, size_t size)
{
    unsigned char entropy[KEYSZ + IVSZ];
    unsigned char* buffer = (unsigned char*) buffer_ptr;

    spin_lock(&random_lock);

    while (0 < size)
    {
        size_t available = rs_have;
        if (size < available)
            available = size;
        if (rs_count < available)
            available = rs_count;

        if (0 < available)
        {
            unsigned char* randomness = rs_buf + sizeof(rs_buf) - rs_have;
            memcpy(buffer, randomness, available);
            memset(randomness, 0, available);
            rs_count -= available;
            rs_have -= available;
            buffer += available;
            size -= available;
        }

        if (rs_count == 0)
        {
            get_entropy((char*) entropy, sizeof(entropy));

            if (rs_initialized)
            {
                unsigned char old_entropy[sizeof(entropy)];
                chacha_keystream(&rs_chacha, old_entropy, sizeof(old_entropy));
                for (size_t i = 0; i < sizeof(entropy); i++)
                    entropy[i] ^= old_entropy[i];
                explicit_bzero(old_entropy, sizeof(old_entropy));
            }

            chacha_keysetup(&rs_chacha, entropy);
            chacha_ivsetup(&rs_chacha, entropy + KEYSZ);
            rs_initialized = true;

            explicit_bzero(entropy, sizeof(entropy));

            rs_have = 0;
            memset(rs_buf, 0, sizeof(rs_buf));

            rs_count = 1600000;
        }

        if (rs_have == 0)
        {
            chacha_keystream(&rs_chacha, rs_buf, sizeof(rs_buf));
            chacha_keysetup(&rs_chacha, rs_buf);
            chacha_ivsetup(&rs_chacha, rs_buf + KEYSZ);
            rs_have = sizeof(rs_buf) - KEYSZ - IVSZ;
        }
    }

    spin_unlock(&random_lock);
}

uint32_t arc4random(void)
{
    uint32_t result;
    arc4random_buf(&result, sizeof(result));
    return result;
}

/*	$OpenBSD: arc4random_uniform.c,v 1.1 2014/07/12 13:24:54 deraadt Exp $	*/

/*
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdint.h>
#include <stdlib.h>

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
uint32_t arc4random_uniform(uint32_t upper_bound)
{
    uint32_t r, min;

    if (upper_bound < 2)
        return 0;

    /* 2**32 % x == (2**32 - x) % x */
    min = -upper_bound % upper_bound;

    /*
     * This could theoretically loop forever but each retry has
     * p > 0.5 (worst case, usually far better) of selecting a
     * number inside the range we need, so it should rarely need
     * to re-roll.
     */
    for (;;)
    {
        r = arc4random();
        if (r >= min)
            break;
    }

    return r % upper_bound;
}
