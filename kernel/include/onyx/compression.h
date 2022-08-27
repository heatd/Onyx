/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_COMPRESSION_H
#define _ONYX_COMPRESSION_H

#include <stddef.h>

#include <onyx/stream.h>

#include <onyx/expected.hpp>
#include <onyx/memory.hpp>
#include <onyx/slice.hpp>

struct file;
namespace compression
{

class module;
/**
 * @brief Register a compression module
 *
 * @param mod Module to register
 */
void register_module(module *mod);

/**
 * @brief Decompression stream
 *
 */
class decompression_stream
{
public:
    virtual expected<size_t, int> decompress_stream(cul::slice<unsigned char> &src,
                                                    cul::slice<unsigned char> dst) = 0;
    virtual ~decompression_stream() = default;
};

class module
{
private:
    const char *name_;

public:
    module(const char *name) :name_{name}
    {
        register_module(this);
    }

    virtual ~module() = default;

    /**
     * @brief Checks if the given compressed blob is supported by this module
     *
     * @param src Compressed data
     * @return True if supported, else false
     */
    virtual bool is_supported(cul::slice<unsigned char> src) = 0;

    /**
     * @brief Decompress a buffer onto dst
     *
     * @param dst Pointer to destination
     * @param dst_capacity Capacity of the destination buffer
     * @param src Slice for the source data
     * @return Number of bytes decompressed, or unexpected
     */
    virtual expected<size_t, int> decompress(void *dst, size_t dst_capacity,
                                             cul::slice<unsigned char> src) = 0;
    virtual expected<unique_ptr<decompression_stream>, int> create_decompression_stream(
        cul::slice<unsigned char> src_hint) = 0;
};

/**
 * @brief Decompress a buffer onto dst
 *
 * @param dst Pointer to destination
 * @param dst_capacity Capacity of the destination buffer
 * @param src Slice for the source data
 * @return Number of bytes decompressed, or unexpected
 */
expected<size_t, int> decompress(void *dst, size_t dst_capacity, cul::slice<unsigned char> src);

expected<unique_ptr<decompression_stream>, int> create_decompression_stream(
    cul::slice<unsigned char> src_hint);

/**
 * @brief Decompression bytestream
 *
 */
class decompress_bytestream : public onx::stream
{
private:
    unique_ptr<decompression_stream> str;
    cul::slice<unsigned char> src;
    void *buf{nullptr};
    size_t len{0};
    size_t pos{0};
    size_t in_buf{0};
    uint8_t eof : 1 {0};
    bool empty() const
    {
        return pos == in_buf;
    }

public:
    decompress_bytestream(unique_ptr<decompression_stream> &&s, cul::slice<unsigned char> src)
        : str{cul::move(s)}, src{cul::move(src)}
    {
    }

    ~decompress_bytestream() override;

    /**
     * @brief Initialize the decompression bytestream
     *
     * @param len Desired length of the buffer
     * @return True if success, else false (out of memory most likely)
     */
    bool init(size_t len);

    /**
     * @brief Read bytes from the stream
     *
     * @param dst Destionation
     * @return Length read, or negative error number
     */
    expected<size_t, int> read(cul::slice<unsigned char> dst) override;

    /**
     * @brief Skip bytes from the stream
     *
     * @param len Length to skip
     * @return Length skipped, or negative error number
     */
    expected<size_t, int> skip(size_t len) override;

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

} // namespace compression

#endif
