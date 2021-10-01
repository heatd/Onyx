/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_STRING_PARSING_H
#define _ONYX_STRING_PARSING_H

#include <onyx/compiler.h>
#include <onyx/expected.hpp>
#include <onyx/string_view.hpp>
#include <type_traits>

namespace parser
{

/**
 * @brief Parse a boolean value from a string_view.
 *
 * @param str String view to parse.
 * @return Expected object containing the value returned, or the error code.
 */
expected<bool, bool> parse_bool_from_string(std::string_view str);

/**
 * @brief Determines if c is a valid character for the base.
 *        Valid bases: 10, 16, 2.
 *
 * @param c The character to check.
 * @param base The base, or radix.
 * @return True if a valid character, false if not.
 */
constexpr bool is_valid_base_x_char(char c, unsigned int base)
{
    if (base == 10)
    {
        return isdigit(c);
    }
    else if (base == 16)
    {
        // Note that uppercase is also valid
        return isxdigit(c);
    }
    else if (base == 2)
    {
        return c == '1' || c == '0';
    }
    else
    {
        // unreachable
        assert(false);
        UNREACHABLE();
    }
}

/**
 * @brief Parse a number from a string_view.
 *
 * @param str String view to parse.
 * @return Expected object containing the value returned, or the error code.
 */
template <typename Type>
expected<Type, bool> parse_number_from_string(std::string_view str)
{
    Type t = 0;
    bool negative = false;

    // Used when looking for 0x and 0b, since we may not assume it's 0,
    // due to negation.
    size_t first_number_idx = 0;

    // May be set if we find a base indicator, like '0x', or '0b'
    unsigned int base = 10;

    if (!str.length())
    {
        return unexpected<bool>{false};
    }

    for (size_t i = 0; i < str.length(); i++)
    {
        char c = str[i];

        if (c == '-') [[unlikely]]
        {
            // Any unsigned parsing doesn't handle '-'
            // We also check for '-' in the middle of the number,
            // like 0x80-90a, which is bogus
            if (i != 0 || std::is_unsigned_v<Type>)
            {
                return unexpected<bool>{false};
            }

            first_number_idx++;

            // Note: we don't handle multiple negations
            // It's fine for our purpose.
            negative = true;
        }
        else if (c == 'x' || c == 'b')
        {
            // First we check if this is actually a 0(x/b) sequence in the
            // beginning of the number, then we switch the base.

            if (i != first_number_idx + 1 || str[first_number_idx] != '0')
            {
                return unexpected<bool>{false};
            }

            if (c == 'x')
            {
                base = 16;
            }
            else if (c == 'b')
            {
                base = 2;
            }
        }
        else if (!is_valid_base_x_char(c, base)) [[unlikely]]
        {
            return unexpected<bool>{false};
        }
        else [[likely]]
        {
            // Might be a good idea to check for multiplication and addition overflows
            int char_value = 0;

            if (isdigit(c))
            {
                char_value = c - '0';
            }
            else if (base == 16)
            {
                // Note the ASCII value of 'a' is higher than that of the uppercase letters.
                // Therefore we handle the uppercase letters in the first condition, and
                // the lowercase in the else. is_valid_base_x_char() has already validated
                // the character, such that it's a digit or between [a, f] or [A, F].
                if (c < 'a')
                {
                    char_value = 10 + c - 'A';
                }
                else
                {
                    char_value = 10 + c - 'a';
                }
            }

            t *= base;
            t += char_value;
        }
    }

    if (negative)
    {
        t = -t;
    }

    return t;
}

} // namespace parser

#endif
