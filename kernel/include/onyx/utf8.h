/*
 * Copyright (c) 2019 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* utf8.h - Contains conversions routines from utf8 to utf32 and vice-versa */

#ifndef _CARBON_UTILS_UTF8_H
#define _CARBON_UTILS_UTF8_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/compiler.h>

typedef uint32_t utf32_t;
typedef uint16_t utf16_t;
typedef uint8_t utf8_t;

#define UTF8_ONE_BYTE                     0x00
#define UTF8_ONE_BYTE_MASK                (1 << 7)
#define UTF8_TWO_BYTES                    0xc0
#define UTF8_TWO_BYTE_MASK                0xe0
#define UTF8_TWO_BYTES_FIRST_VALID_MASK   0x1f
#define UTF8_THREE_BYTES                  0xe0
#define UTF8_THREE_BYTE_MASK              0xf0
#define UTF8_THREE_BYTES_FIRST_VALID_MASK 0xf
#define UTF8_FOUR_BYTES                   0xf0
#define UTF8_FOUR_BYTE_MASK               0xf8
#define UTF8_FOUR_BYTES_FIRST_VALID_MASK  0x7
#define UTF8_CONTINUATION_BYTE_MASK       0xc0
#define UTF8_CONTINUATION                 0x80
#define UTF8_CONTINUATION_BYTE_VALID_MASK 0x3f

#define UTF_INVALID_CODEPOINT   (utf32_t) - 1
#define UTF_ERROR_SURROGATE     (size_t) - 1
#define UTF_ERROR_OVERLONG      (size_t) - 2
#define UTF_ERROR_BAD_CODEPOINT (size_t) - 3

#define UTF_IS_ERROR(ret) ((ssize_t) ret < 0)

#define UTF_CONV_ERROR_RET            \
    {                                 \
        return UTF_INVALID_CODEPOINT; \
    }

static inline bool utf8_is_surrogate(utf32_t codepoint)
{
    return (codepoint >= 0xD800 && codepoint <= 0xDFFF);
}

static inline bool utf8_is_overlong(utf32_t codepoint, size_t *plen)
{
    size_t len = *plen;
    if (len > 1)
    {
        if (unlikely(codepoint <= 0x7f))
            return true;
        if (unlikely(len > 2 && codepoint <= 0x7ff))
            return true;
        if (unlikely(len > 3 && codepoint <= 0xffff))
            return true;
    }

    return false;
}

static inline utf32_t utf8_ret_codepoint(utf32_t codepoint, size_t *plen)
{
    bool surrogate = utf8_is_surrogate(codepoint);
    bool overlong = utf8_is_overlong(codepoint, plen);
    if (surrogate)
        *plen = UTF_ERROR_SURROGATE;
    if (overlong)
        *plen = UTF_ERROR_OVERLONG;
    return overlong || surrogate ? UTF_INVALID_CODEPOINT : codepoint;
}

static utf32_t utf8to32(const utf8_t *buf, size_t length, size_t *plen)
{
    utf8_t first = *buf;
    utf32_t codepoint;

    if ((first & UTF8_ONE_BYTE_MASK) == UTF8_ONE_BYTE)
    {
        *plen = 1;
        return first;
    }
    else if ((first & UTF8_TWO_BYTE_MASK) == UTF8_TWO_BYTES)
    {
        *plen = 2;
        if (length < 2)
            UTF_CONV_ERROR_RET;
        codepoint = (first & UTF8_TWO_BYTES_FIRST_VALID_MASK) << 6;
        if ((buf[1] & UTF8_CONTINUATION_BYTE_MASK) != UTF8_CONTINUATION)
            UTF_CONV_ERROR_RET;

        codepoint |= ((buf[1] & UTF8_CONTINUATION_BYTE_VALID_MASK) << 0);
        return utf8_ret_codepoint(codepoint, plen);
    }
    else if ((first & UTF8_THREE_BYTE_MASK) == UTF8_THREE_BYTES)
    {
        *plen = 3;
        if (length < 3)
            UTF_CONV_ERROR_RET;
        codepoint = (first & UTF8_THREE_BYTES_FIRST_VALID_MASK) << (6 + 6);
        if ((buf[1] & UTF8_CONTINUATION_BYTE_MASK) != UTF8_CONTINUATION)
            UTF_CONV_ERROR_RET;

        codepoint |= ((buf[1] & UTF8_CONTINUATION_BYTE_VALID_MASK) << 6);
        if ((buf[2] & UTF8_CONTINUATION_BYTE_MASK) != UTF8_CONTINUATION)
            UTF_CONV_ERROR_RET;

        codepoint |= ((buf[2] & UTF8_CONTINUATION_BYTE_VALID_MASK) << 0);
        return utf8_ret_codepoint(codepoint, plen);
    }
    else if ((first & UTF8_FOUR_BYTE_MASK) == UTF8_FOUR_BYTES)
    {
        if (length < 4)
            UTF_CONV_ERROR_RET;
        codepoint = (first & UTF8_FOUR_BYTES_FIRST_VALID_MASK) << (6 + 6 + 6);
        if ((buf[1] & UTF8_CONTINUATION_BYTE_MASK) != UTF8_CONTINUATION)
            UTF_CONV_ERROR_RET;

        codepoint |= ((buf[1] & UTF8_CONTINUATION_BYTE_VALID_MASK) << (6 + 6));
        if ((buf[2] & UTF8_CONTINUATION_BYTE_MASK) != UTF8_CONTINUATION)
            UTF_CONV_ERROR_RET;

        codepoint |= ((buf[2] & UTF8_CONTINUATION_BYTE_VALID_MASK) << 6);
        if ((buf[3] & UTF8_CONTINUATION_BYTE_MASK) != UTF8_CONTINUATION)
            UTF_CONV_ERROR_RET;

        codepoint |= ((buf[2] & UTF8_CONTINUATION_BYTE_VALID_MASK) << 0);
        *plen = 4;
        return utf8_ret_codepoint(codepoint, plen);
    }
    else
    {
        *plen = 1;
        UTF_CONV_ERROR_RET;
    }
}

struct utf8_output
{
    utf8_t bytes[4];
};

static size_t utf32to8(struct utf8_output *out, utf32_t codepoint)
{
    size_t nr_bytes;
    if (utf8_is_surrogate(codepoint))
        return UTF_ERROR_SURROGATE;

    if (codepoint < 0x80)
        nr_bytes = 1;
    else if (codepoint < 0x800)
        nr_bytes = 2;
    else if (codepoint < 0x10000)
        nr_bytes = 3;
    else if (codepoint < 0x10ffff)
        nr_bytes = 4;
    else
        return UTF_ERROR_BAD_CODEPOINT;

    if (nr_bytes == 1)
    {
        out->bytes[0] = (utf8_t) codepoint;
        return 1;
    }
    else if (nr_bytes == 2)
    {
        out->bytes[1] = UTF8_CONTINUATION | (codepoint & UTF8_CONTINUATION_BYTE_VALID_MASK);
        out->bytes[0] = UTF8_TWO_BYTES | ((codepoint >> 6) & UTF8_TWO_BYTES_FIRST_VALID_MASK);
        return 2;
    }
    else if (nr_bytes == 3)
    {
        out->bytes[2] = UTF8_CONTINUATION | (codepoint & UTF8_CONTINUATION_BYTE_VALID_MASK);
        out->bytes[1] = UTF8_CONTINUATION | ((codepoint >> 6) & UTF8_CONTINUATION_BYTE_VALID_MASK);
        out->bytes[0] = UTF8_THREE_BYTES | ((codepoint >> 12) & UTF8_THREE_BYTES_FIRST_VALID_MASK);
        return 3;
    }
    else if (nr_bytes == 4)
    {
        out->bytes[3] = UTF8_CONTINUATION | (codepoint & UTF8_CONTINUATION_BYTE_VALID_MASK);
        out->bytes[2] = UTF8_CONTINUATION | ((codepoint >> 6) & UTF8_CONTINUATION_BYTE_VALID_MASK);
        out->bytes[1] = UTF8_CONTINUATION | ((codepoint >> 12) & UTF8_CONTINUATION_BYTE_VALID_MASK);
        out->bytes[0] = UTF8_FOUR_BYTES | ((codepoint >> 18) & UTF8_FOUR_BYTES_FIRST_VALID_MASK);
        return 4;
    }

    __builtin_unreachable();
}

static size_t ucs2to8(struct utf8_output *out, utf16_t codepoint)
{
    size_t nr_bytes;
    if (utf8_is_surrogate(codepoint))
        return UTF_ERROR_SURROGATE;

    if (codepoint < 0x80)
        nr_bytes = 1;
    else if (codepoint < 0x800)
        nr_bytes = 2;
    else
        return UTF_ERROR_BAD_CODEPOINT;

    if (nr_bytes == 1)
    {
        out->bytes[0] = (utf8_t) codepoint;
        return 1;
    }
    else if (nr_bytes == 2)
    {
        out->bytes[1] = UTF8_CONTINUATION | (codepoint & UTF8_CONTINUATION_BYTE_VALID_MASK);
        out->bytes[0] = UTF8_TWO_BYTES | ((codepoint >> 6) & UTF8_TWO_BYTES_FIRST_VALID_MASK);
        return 2;
    }

    __builtin_unreachable();
}

#endif
