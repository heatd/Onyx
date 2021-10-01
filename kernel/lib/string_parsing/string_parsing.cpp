/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <ctype.h>
#include <onyx/string_parsing.h>

namespace parser
{

const char *truthy_strings[] = {"true", "yes", "y", "Y"};
const char *falsy_strings[] = {"false", "no", "n", "N"};

/**
 * @brief Parse a boolean value from a string_view.
 *
 * @param str String view to parse.
 * @return Expected object containing the value returned, or the error code.
 */
expected<bool, bool> parse_bool_from_string(std::string_view str)
{
    // Bad input
    if (str.empty())
    {
        return unexpected<bool>{false};
    }

    // We may take bool as a number
    if (isdigit(str[0]))
    {
        auto ex = parse_number_from_string<uint8_t>(str);

        if (!ex)
            return unexpected<bool>{false};

        auto num = ex.value();

        // We reject any number that's not 0 or 1
        if (num != 0 && num != 1)
        {
            return unexpected<bool>{false};
        }

        return (bool)num;
    }

    // Parse any truthy-falsy text

    for (const auto &truth_str : truthy_strings)
    {
        if (str == truth_str)
        {
            return true;
        }
    }

    for (const auto &false_str : falsy_strings)
    {
        if (str == false_str)
        {
            return false;
        }
    }

    return unexpected<bool>{false};
}

} // namespace parser
