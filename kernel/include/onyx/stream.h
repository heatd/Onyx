/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_STREAM_H
#define _ONYX_STREAM_H

#include <stddef.h>

#include <onyx/expected.hpp>
#include <onyx/slice.hpp>

struct file;
namespace onx
{

class stream
{
public:
    virtual ~stream() = default;
    /**
     * @brief Read bytes from the stream
     *
     * @param dst Destionation
     * @return Length read, or negative error number
     */
    virtual expected<size_t, int> read(cul::slice<unsigned char> dst) = 0;

    /**
     * @brief Skip bytes from the stream
     *
     * @param len Length to skip
     * @return Length skipped, or negative error number
     */
    virtual expected<size_t, int> skip(size_t len) = 0;

    /**
     * @brief Splice the stream onto a file
     *
     * @param len Length of the splicing
     * @param f File to splice to
     * @param src Compressed source
     * @return Length, or negative error code
     */
    virtual expected<size_t, int> splice(size_t len, file *f) = 0;
};

} // namespace onx
#endif
