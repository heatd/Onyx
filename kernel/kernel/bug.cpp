/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/bug.h>
#include <onyx/cpu.h>
#include <onyx/process.h>

#ifndef ARCH_SUPPORTS_BUGON

/* Generic WARN handler */
void generic_warn(const char *filename, int line)
{
    pr_warn("WARNING: CPU: %u PID: %d at %s:%u %pS\n", get_cpu_nr(),
            get_current_process() ? get_current_process()->pid_ : 0, filename, line,
            __builtin_return_address(0));
}

#endif
