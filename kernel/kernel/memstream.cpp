/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/memstream.h>
#include <onyx/vfs.h>

/**
 * @brief Splice the stream onto a file
 *
 * @param len Length of the splicing
 * @param f File to splice to
 * @param src Compressed source
 * @return Length, or negative error code
 */
expected<size_t, int> onx::memstream::splice(size_t len, file *f)
{
    const auto l = cul::min(len, src.size_bytes());
    if (ssize_t st = write_vfs(f->f_seek, len, src.data(), f); st < 0)
        return unexpected<int>((int) st);
    src.adjust(l);
    f->f_seek += l;
    return l;
}
