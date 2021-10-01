/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/cmdline.h>
#include <onyx/hashtable.hpp>
#include <onyx/log.h>
#include <onyx/string_view.hpp>
#include <string.h>
#include <cstddef>

char kernel_cmdline[COMMAND_LINE_LENGTH + 1];

/**
 * @brief Set the kernel's command line.
 * Should be used by boot protocol code.
 *
 * @param cmdl Pointer to a null terminated kernel command line string.
 *             This string should only contain arguments.
 */
void set_kernel_cmdline(const char *cmdl)
{
    auto cmdl_size = strlcpy(kernel_cmdline, cmdl, COMMAND_LINE_LENGTH + 1);

    if (cmdl_size > COMMAND_LINE_LENGTH)
    {
        WARN("cmdline", "Command line of length %zu truncated\n", cmdl_size);
    }
}

namespace cmdline
{

cul::hashtable2<kparam::kernel_param, 12, fnv_hash_t, kparam::kernel_param::hash_kparam> param_list;

void handle_arg(std::string_view arg)
{
    // TODO: Actually handle arguments
    // I haven't finished this because honestly, I've gotten bored.
}

/**
 * @brief Handle parameters.
 *
 */
void init()
{
    std::string_view sv{kernel_cmdline};
    const char *arg_start = nullptr;

    bool parsing_arg = false;

    bool in_quotes = false;

    printk("args: %.*s\n", (int) sv.length(), sv.data());

    for (size_t i = 0; i < sv.length(); i++)
    {
        char c = sv[i];
        if (isspace(c) && !in_quotes)
        {
            if (!parsing_arg)
            {
                continue;
            }
            else
            {
                std::string_view arg{arg_start, &sv[i]};

                handle_arg(arg);

                parsing_arg = false;
            }
        }
        else
        {
            if (c == '\"')
            {
                in_quotes = !in_quotes;
            }

            if (!parsing_arg)
            {
                parsing_arg = true;
                arg_start = &sv[i];
            }
        }
    }

    // Handle trailing args
    if (parsing_arg)
    {
        std::string_view arg{arg_start, &sv[sv.length()]};

        handle_arg(arg);
    }
}

} // namespace cmdline
