/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/compression.h>
#include <onyx/panic.h>

#include "zstd/lib/zstd.h"
#include "zstd/lib/zstd_errors.h"

#include <onyx/memory.hpp>

namespace compression::zstd
{

class zstd_decompression_stream : public decompression_stream
{
    ZSTD_DStream* dstr{nullptr};

public:
    zstd_decompression_stream(cul::slice<unsigned char> src_hint)
    {
    }

    ~zstd_decompression_stream() override
    {
        ZSTD_freeDStream(dstr);
    }

    bool init()
    {
        dstr = ZSTD_createDStream();
        return dstr != nullptr;
    }

    expected<size_t, int> decompress_stream(cul::slice<unsigned char>& src,
                                            cul::slice<unsigned char> dst) final
    {
        if (src.size_bytes() == 0)
            return 0;

        ZSTD_outBuffer output_buf{dst.data(), dst.size_bytes(), 0};
        ZSTD_inBuffer input_buf{src.data(), src.size_bytes(), 0};
        auto st = ZSTD_decompressStream(dstr, &output_buf, &input_buf);
        if (ZSTD_isError(st))
        {
            panic("ZSTD compression error: %s\n", ZSTD_getErrorName(st));
        }

        // printk("Consumed %zu from %p, read %zu\n", input_buf.pos, src.data(), output_buf.pos);
        src.adjust(input_buf.pos);

        return output_buf.pos;
    }
};

class zstd_module : public compression::module
{
public:
    zstd_module() : compression::module{"zstd"}
    {
    }
    /**
     * @brief Decompress a buffer onto dst
     *
     * @param dst Pointer to destination
     * @param dst_capacity Capacity of the destination buffer
     * @param src Slice for the source data
     * @return Number of bytes decompressed, or unexpected
     */
    expected<size_t, int> decompress(void* dst, size_t dst_capacity,
                                     cul::slice<unsigned char> src) final
    {
        auto size = ZSTD_decompress(dst, dst_capacity, src.data(), src.size_bytes());
        if (ZSTD_isError(size))
        {
            if (ZSTD_getErrorCode(size) == ZSTD_error_dstSize_tooSmall)
                return unexpected<int>{-ENOSPC};
            printk("zstd: Error decompressing buffer: %s\n", ZSTD_getErrorName(size));
            return unexpected<int>(-EINVAL);
        }

        return size;
    }

    /**
     * @brief Checks if the given compressed blob is supported by this module
     *
     * @param src Compressed data
     * @return True if supported, else false
     */
    bool is_supported(cul::slice<unsigned char> src) final
    {
        if (src.size_bytes() < 4)
            return false;
        return src[0] == 0x28 && src[1] == 0xb5 && src[2] == 0x2f && src[3] == 0xfd;
    }

    expected<unique_ptr<compression::decompression_stream>, int> create_decompression_stream(
        cul::slice<unsigned char> src_hint) override
    {
        auto str = make_unique<zstd_decompression_stream>(src_hint);
        if (!str)
            return unexpected<int>{-ENOMEM};
        if (!str->init())
            return unexpected<int>{-ENOMEM};
        return str.cast<compression::decompression_stream>();
    }
};

zstd_module zstd{};

} // namespace compression::zstd
