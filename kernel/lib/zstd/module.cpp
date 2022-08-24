/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/compression.h>
#include <onyx/panic.h>

#include "zstd/lib/zstd.h"
#include "zstd/lib/zstd_errors.h"

namespace compression::zstd
{

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
    expected<size_t, int> decompress(void *dst, size_t dst_capacity,
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

#if 0
    /**
     * @brief Decompress a buffer onto dst
     *
     * @param dst Pointer to destination
     * @param dst_capacity Capacity of the destination buffer
     * @param src Slice for the source data
     * @return Number of bytes decompressed, or unexpected
     */
    expected<size_t, int> decompress_stream(
        void *dst, size_t dst_capacity, cul::slice<unsigned char> src,
        expected<cul::slice<void *>, int> (*increase_dst_size)(cul::slice<unsigned char> dst))
    {
        ZSTD_DStream *dstr = ZSTD_createDStream();
        ZSTD_outBuffer output_buf{dst, dst_capacity, 0};
        ZSTD_inBuffer input_buf{src.data(), src.size_bytes(), 0};

        while (true)
        {
            auto st = ZSTD_decompressStream(dstr, &output_buf, &input_buf);

            if (st > 0)
            {
                auto slice =
                    increase_dst_size(cul::slice<unsigned char>{dst, dst_capacity}).unwrap();
                dst = slice.data();
                dst_capacity = slice.size_bytes();
                output_buf.dst = dst;
                output_buf.size = dst_capacity;
            }
        }

        printk("Done decompression: Final buffer size %u bytes\n", dst_capacity);

        ZSTD_freeDStream(dstr);
    }
#endif
};

zstd_module zstd{};

} // namespace compression::zstd
