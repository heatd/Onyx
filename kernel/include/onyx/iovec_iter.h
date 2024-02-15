/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_IOVEC_ITER_H
#define _ONYX_IOVEC_ITER_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <onyx/types.h>

enum iovec_type
{
    IOVEC_USER = 0,
    IOVEC_KERNEL
};

#ifdef __cplusplus

#include <onyx/assert.h>
#include <onyx/compiler.h>

#include <onyx/slice.hpp>
#include <onyx/utility.hpp>

struct iovec_iter
{
    cul::slice<iovec> vec;
    size_t pos_{0};
    size_t bytes;
    enum iovec_type type;

    iovec_iter(cul::slice<iovec> vec, size_t length, enum iovec_type type = IOVEC_USER)
        : vec{cul::move(vec)}, bytes{length}, type{type}
    {
        if (length > 0)
            skip_zero_len();
    }

    void skip_zero_len()
    {
        /* Required so users never need to explicitly handle zero-len iov_lens. It's all handled by
         * skip_zero_len in the ctor, and advance().
         */
        while (vec.front().iov_len == 0)
            vec.adjust(1);
    }

    [[nodiscard]] bool empty()
    {
        return vec.size() == 0;
    }

    [[nodiscard]] iovec curiovec() const
    {
        return {(void *) ((u8 *) vec.front().iov_base + pos_), vec.front().iov_len - pos_};
    }

    void advance(size_t len)
    {
        const auto &cur = vec.front();

        DCHECK(cur.iov_len >= pos_ + len);
        DCHECK(bytes >= len);
        pos_ += len;
        bytes -= len;

        while (!empty() && pos_ == vec.front().iov_len)
        {
            vec.adjust(1);
            pos_ = 0;
        }
    }
};
#else

/* Opaque definition of iovec_iter */
struct iovec_iter;

#endif

static inline ssize_t iovec_count_length(struct iovec *vec, unsigned int n)
{
    ssize_t length = 0;

    while (n--)
    {
        if ((ssize_t) vec->iov_len < 0)
            return -EINVAL;

        if (__builtin_saddl_overflow(length, vec->iov_len, &length))
            return -EINVAL;

        vec++;
    }

    return length;
}

/**
 * @brief Copy data from the iterator to the kernel
 *
 * @param iter iovec iterator
 * @param buf Buffer
 * @param len Length
 * @return Bytes copied on success, or negative error codes
 */
ssize_t copy_from_iter(struct iovec_iter *iter, void *buf, size_t len);

/**
 * @brief Copy data from the kernel to the iterator
 *
 * @param iter iovec iterator
 * @param buf Buffer
 * @param len Length
 * @return Bytes copied on success, or negative error codes
 */
ssize_t copy_to_iter(struct iovec_iter *iter, const void *buf, size_t len);

/**
 * @brief Check if all buffers' addresses and lengths are aligned
 *
 * @param iter iovec iterateor
 * @param alignment Alignment. Must be a power of 2
 * @return True if aligned, else false
 */
bool iovec_is_aligned(struct iovec_iter *iter, unsigned long alignment);

#endif
