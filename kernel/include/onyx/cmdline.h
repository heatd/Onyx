/*
 * Copyright (c) 2021 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_CMDLINE_H
#define _ONYX_CMDLINE_H

#include <ctype.h>

#include <onyx/compiler.h>
#include <onyx/fnv.h>
#include <onyx/list.h>

__BEGIN_CDECLS

#define COMMAND_LINE_LENGTH 1024

/**
 * @brief Set the kernel's command line.
 * Should be used by boot protocol code.
 *
 * @param cmdl Pointer to a null terminated kernel command line string.
 *             This string should only contain arguments.
 */
void set_kernel_cmdline(const char *cmdl);

void cmdline_init(void);

struct cmdline_param
{
    const char *name;
    int (*handler)(const char *str);
};

#define kernel_param(name, handler)                                                        \
    __attribute__((section(".rodata.kparam"), used,                                        \
                   aligned(8))) static const struct cmdline_param __PASTE(kparam_,         \
                                                                          __COUNTER__) = { \
        (name), (handler)};

__END_CDECLS

#endif
