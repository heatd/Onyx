/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>

#include <onyx/compression.h>
#include <onyx/vector.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

namespace compression
{

cul::vector<module *> modules;

/**
 * @brief Register a compression module
 *
 * @param mod Module to register
 */
void register_module(module *mod)
{
    assert(modules.push_back(mod) == true);
}

/**
 * @brief Decompress a buffer onto dst
 *
 * @param dst Pointer to destination
 * @param dst_capacity Capacity of the destination buffer
 * @param src Slice for the source data
 * @return Number of bytes decompressed, or unexpected
 */
expected<size_t, int> decompress(void *dst, size_t dst_capacity, cul::slice<unsigned char> src)
{
    for (auto mod : modules)
    {
        if (mod->is_supported(src))
            return mod->decompress(dst, dst_capacity, src);
    }

    return unexpected<int>{-ENOTSUP};
}

expected<unique_ptr<decompression_stream>, int> create_decompression_stream(
    cul::slice<unsigned char> src_hint)
{
    for (auto mod : modules)
    {
        if (mod->is_supported(src_hint))
            return mod->create_decompression_stream(src_hint);
    }

    return unexpected<int>{-ENOTSUP};
}

bool decompress_bytestream::init(size_t len)
{
    buf = vmalloc(vm_size_to_pages(len), VM_TYPE_REGULAR, VM_WRITE | VM_READ, GFP_KERNEL);
    if (!buf)
        return false;
    this->len = len;
    return true;
}

decompress_bytestream::~decompress_bytestream()
{
    if (buf)
        vfree((void *) buf);
}

expected<size_t, int> decompress_bytestream::read(cul::slice<unsigned char> dst)
{
    auto dstp = dst.data();
    auto len = dst.size_bytes();
    size_t consumed = 0;
    if (eof)
        return 0;
    assert(in_buf >= pos);
    while (len != 0)
    {
        if (!empty())
        {
            auto to_copy = min(len, in_buf - pos);
            memcpy(dstp, (unsigned char *) buf + pos, to_copy);
            pos += to_copy;
            consumed += to_copy;
            dstp += to_copy;
            len -= to_copy;
        }
        else
        {
            // Decompress some bytes
            auto ex = str->decompress_stream(
                src, cul::slice<unsigned char>{(unsigned char *) buf, this->len});
            if (ex.has_error())
                return unexpected<int>{ex.error()};
            if (ex.value() == 0)
            {
                eof = 1;
                return len;
            }

            pos = 0;
            in_buf = ex.value();
        }
    }

    return consumed;
}

expected<size_t, int> decompress_bytestream::skip(size_t len)
{
    // Skip what we can in the buffer first
    auto l = min(len, in_buf - pos);
    size_t skipped = 0;
    pos += l;
    len -= l;
    skipped += l;

    assert(in_buf >= pos);
    while (len)
    {
        auto ex = str->decompress_stream(
            src, cul::slice<unsigned char>{(unsigned char *) buf, this->len});
        if (ex.has_error())
            return unexpected<int>{ex.error()};
        if (ex.value() == 0)
        {
            eof = 1;
            return skipped;
        }

        in_buf = ex.value();
        pos = min(len, in_buf);
        len -= pos;
        skipped += pos;
    }

    return skipped;
}

/**
 * @brief Splice the stream onto a file
 *
 * @param len Length of the splicing
 * @param f File to splice to
 * @param src Compressed source
 * @return Length, or negative error code
 */
expected<size_t, int> decompress_bytestream::splice(size_t len, file *f)
{
    size_t consumed = 0;
    if (eof)
        return 0;
    assert(in_buf >= pos);
    while (len != 0)
    {
        if (!empty())
        {
            auto consume_inbuf = min(len, in_buf - pos);
            if (ssize_t st = write_vfs(f->f_seek, consume_inbuf, (unsigned char *) buf + pos, f);
                st < 0)
                return unexpected<int>{(int) st};
            pos += consume_inbuf;
            consumed += consume_inbuf;
            f->f_seek += consume_inbuf;
            len -= consume_inbuf;
        }
        else
        {
            // Decompress some bytes
            auto ex = str->decompress_stream(
                src, cul::slice<unsigned char>{(unsigned char *) buf, this->len});
            if (ex.has_error())
                return unexpected<int>{ex.error()};
            if (ex.value() == 0)
            {
                eof = 1;
                return len;
            }

            pos = 0;
            in_buf = ex.value();
        }
    }

    return consumed;
}

} // namespace compression
