/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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
