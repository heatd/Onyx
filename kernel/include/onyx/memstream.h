/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_MEMSTREAM_H
#define _ONYX_MEMSTREAM_H

#include <stddef.h>
#include <string.h>

#include <onyx/stream.h>

#include <onyx/expected.hpp>
#include <onyx/slice.hpp>

struct file;
namespace onx
{

class memstream : public onx::stream
{
    cul::slice<unsigned char> src;

public:
    memstream(cul::slice<unsigned char> s) : src(cul::move(s))
    {
    }
    /**
     * @brief Read bytes from the stream
     *
     * @param dst Destionation
     * @return Length read, or negative error number
     */
    expected<size_t, int> read(cul::slice<unsigned char> dst) override
    {
        const auto l = cul::min(dst.size_bytes(), src.size_bytes());
        memcpy(dst.data(), src.data(), l);
        src.adjust(l);
        return l;
    }

    /**
     * @brief Skip bytes from the stream
     *
     * @param len Length to skip
     * @return Length skipped, or negative error number
     */
    expected<size_t, int> skip(size_t len) override
    {
        const auto l = cul::min(len, src.size_bytes());
        src.adjust(l);
        return l;
    }

    /**
     * @brief Splice the stream onto a file
     *
     * @param len Length of the splicing
     * @param f File to splice to
     * @param src Compressed source
     * @return Length, or negative error code
     */
    expected<size_t, int> splice(size_t len, file *f) override;
};

} // namespace onx
#endif
