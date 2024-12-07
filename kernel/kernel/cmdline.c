/*
 * Copyright (c) 2021 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stddef.h>
#include <string.h>

#include <onyx/bug.h>
#include <onyx/cmdline.h>
#include <onyx/log.h>

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
    size_t cmdl_size = strlcpy(kernel_cmdline, cmdl, COMMAND_LINE_LENGTH + 1);
    WARN_ON(cmdl_size > COMMAND_LINE_LENGTH);
}

extern const struct cmdline_param __start_kparam[], __end_kparam[];

static void do_arg(const char *start, const char *end)
{
    char buf[128];
    char *p = buf;
    char *eq;
    char *val_start = NULL;
    const struct cmdline_param *param;

    if (WARN_ON(end - start >= 128))
        return;
    memcpy(buf, start, end - start);
    buf[end - start] = '\0';

    /* Skip leading dashes, for backward compat with --root */
    while (*p == '-')
        p++;
    eq = strchr(p, '=');
    if (eq)
    {
        char *quotes, *quotes_end;
        *eq = '\0';
        quotes = strchr(p + 1, '"');
        if (quotes)
        {
            quotes_end = strchr(quotes + 1, '"');
            if (WARN_ON(!quotes_end))
                return;
            *quotes_end = '\0';
            val_start = quotes + 1;
        }
        else
            val_start = eq + 1;
    }

    param = __start_kparam;

    do
    {
        if (!strcmp(param->name, p))
        {
            if (param->handler(val_start))
                break;
        }
    } while (param++ < __end_kparam);
}

/**
 * @brief Handle parameters.
 *
 */
void cmdline_init(void)
{
    bool parsing_arg = false;
    bool in_quotes = false;
    const char *start, *p;
    start = p = kernel_cmdline;
    pr_warn("cmdline %s\n", kernel_cmdline);
    size_t len = strlen(kernel_cmdline);

    for (size_t i = 0; i < len; i++, p++)
    {
        if (isspace(*p))
        {
            if (!parsing_arg || in_quotes)
                continue;
            do_arg(start, p);
            parsing_arg = false;
            continue;
        }

        if (*p == '"' || *p == '\'')
        {
            in_quotes = !in_quotes;
            continue;
        }

        if (!in_quotes && !parsing_arg)
        {
            /* Not in quotes, not a space - looks like a start of an argument */
            start = p;
            parsing_arg = true;
        }
    }

    if (parsing_arg)
        do_arg(start, p);
}
