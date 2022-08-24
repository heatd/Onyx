/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>

#include <onyx/compression.h>
#include <onyx/vector.h>

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

} // namespace compression
