/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_IOVEC_ITER_H
#define _ONYX_IOVEC_ITER_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <onyx/compiler.h>
#include <onyx/types.h>

enum iovec_type
{
    IOVEC_USER = 0,
    IOVEC_KERNEL
};

#ifdef __cplusplus
#include <onyx/slice.hpp>
#include <onyx/utility.hpp>
#endif
#include <onyx/assert.h>

__BEGIN_CDECLS
struct iovec_iter;

void iovec_iter_advance(struct iovec_iter *iter, size_t len);

struct iovec_iter
{
    union {
        const struct iovec *vec;
    };
    size_t nr_vecs;
    size_t pos_;
    size_t bytes;
    enum iovec_type type;

#ifdef __cplusplus
    iovec_iter(cul::slice<iovec> vec, size_t length, enum iovec_type type = IOVEC_USER)
        : vec{vec.cbegin()}, nr_vecs{vec.size()}, pos_{0}, bytes{length}, type{type}
    {
        if (length > 0)
            skip_zero_len();
    }

    void skip_zero_len()
    {
        /* Required so users never need to explicitly handle zero-len iov_lens. It's all handled by
         * skip_zero_len in the ctor, and advance().
         */
        if (type != IOVEC_USER)
            return;
        while (vec->iov_len == 0)
        {
            vec++;
            nr_vecs--;
        }
    }

    [[nodiscard]] bool empty()
    {
        return nr_vecs == 0;
    }

    [[nodiscard]] iovec curiovec() const
    {
        return {(void *) ((u8 *) vec->iov_base + pos_), vec->iov_len - pos_};
    }

    void advance(size_t len)
    {
        iovec_iter_advance(this, len);
    }
#endif
};

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

static inline size_t iovec_iter_bytes(struct iovec_iter *iter)
{
    return iter->bytes;
}

static inline bool iovec_iter_empty(struct iovec_iter *iter)
{
    return iter->nr_vecs == 0;
}

__END_CDECLS

#endif
