/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_UTFSTRING_H
#define _ONYX_UTFSTRING_H

#include <errno.h>

#include <onyx/culstring.h>
#include <onyx/utf8.h>

#include <onyx/expected.hpp>

expected<cul::string, int> string_from_ucs2str(utf16_t *str)
{
    cul::string s;
    while (*str)
    {
        utf8_output out;
        size_t size = ucs2to8(&out, *str);
        if (UTF_IS_ERROR(size))
            return unexpected<int>(-EILSEQ);
        if (!s.append({(char *) out.bytes, size}))
            return unexpected<int>{-ENOMEM};
        str++;
    }

    return s;
}

#endif
