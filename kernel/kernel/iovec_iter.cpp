/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <string.h>

#include <onyx/iovec_iter.h>
#include <onyx/vm.h>

/**
 * @brief Copy data from the iterator to the kernel
 *
 * @param iter iovec iterator
 * @param buf Buffer
 * @param len Length
 * @return Bytes copied on success, or negative error codes
 */
ssize_t copy_from_iter(iovec_iter *iter, void *buf, size_t len)
{
    ssize_t st = 0;
    u8 *p = (u8 *) buf;
    while (!iter->empty())
    {
        iovec iov = iter->curiovec();
        if (iov.iov_len == 0)
        {
            /* Skip over zero-sized iovs */
            iter->advance(0);
            continue;
        }

        ssize_t to_copy = cul::min(len, iov.iov_len);
        ssize_t status = 0;
        /* Decide the copy strategy based on iter::type */
        if (iter->type == IOVEC_KERNEL)
            memcpy(p, iov.iov_base, to_copy);
        else if (iter->type == IOVEC_USER)
            status = copy_from_user(p, iov.iov_base, to_copy);

        if (status < 0)
            return st ?: status;
        iter->advance(to_copy);
        len -= to_copy;
        st += to_copy;
        p += to_copy;
        if (!len)
            break;
    }

    return st;
}

/**
 * @brief Copy data from the kernel to the iterator
 *
 * @param iter iovec iterator
 * @param buf Buffer
 * @param len Length
 * @return Bytes copied on success, or negative error codes
 */
ssize_t copy_to_iter(iovec_iter *iter, const void *buf, size_t len)
{
    ssize_t st = 0;
    const u8 *p = (const u8 *) buf;
    while (!iter->empty())
    {
        iovec iov = iter->curiovec();
        if (iov.iov_len == 0)
        {
            /* Skip over zero-sized iovs */
            iter->advance(0);
            continue;
        }

        ssize_t to_copy = cul::min(len, iov.iov_len);
        ssize_t status = 0;
        /* Decide the copy strategy based on iter::type */
        if (iter->type == IOVEC_KERNEL)
            memcpy(iov.iov_base, p, to_copy);
        else if (iter->type == IOVEC_USER)
            status = copy_to_user(iov.iov_base, p, to_copy);

        if (status < 0)
            return st ?: status;
        iter->advance(to_copy);
        len -= to_copy;
        st += to_copy;
        p += to_copy;
        if (!len)
            break;
    }

    return st;
}

void iovec_iter_advance(struct iovec_iter *iter, size_t len)
{
    const auto cur = iter->vec;
    DCHECK(cur->iov_len >= iter->pos_ + len);
    DCHECK(iter->bytes >= len);
    iter->pos_ += len;
    iter->bytes -= len;

    while (!iter->empty() && iter->pos_ == iter->vec->iov_len)
    {
        iter->vec++;
        iter->nr_vecs--;
        iter->pos_ = 0;
    }
}

/**
 * @brief Check if all buffers' addresses and lengths are aligned
 *
 * @param iter iovec iterateor
 * @param alignment Alignment. Must be a power of 2
 * @return True if aligned, else false
 */
bool iovec_is_aligned(struct iovec_iter *iter, unsigned long alignment)
{
    bool first = true;
    for (size_t i = 0; i < iter->nr_vecs; i++)
    {
        const auto &v = iter->vec[i];
        unsigned long addr = (unsigned long) v.iov_base;
        unsigned long len = v.iov_len;

        if (first)
        {
            /* If we're the first iov, take into account the pos_ (if we've iterated through this
             * iov before). */
            addr += iter->pos_;
            len -= iter->pos_;
        }

        if (addr & (alignment - 1))
            return false;
        if (len & (alignment - 1))
            return false;
        first = false;
    }

    return true;
}
