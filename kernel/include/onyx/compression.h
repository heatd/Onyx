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

#include <onyx/expected.hpp>
#include <onyx/slice.hpp>

namespace compression
{

class module;
/**
 * @brief Register a compression module
 *
 * @param mod Module to register
 */
void register_module(module *mod);

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

} // namespace compression

#endif
