/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_IOVEC_ITER_H
#define _ONYX_IOVEC_ITER_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/assert.h>
#include <onyx/types.h>

#include <onyx/slice.hpp>
#include <onyx/utility.hpp>

struct iovec_iter
{
    cul::slice<iovec> vec;
    size_t pos_{0};
    size_t bytes;

    iovec_iter(cul::slice<iovec> vec, size_t length) : vec{cul::move(vec)}, bytes{length}
    {
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

        if (pos_ == cur.iov_len)
            vec.adjust(1);
    }
};

#endif
