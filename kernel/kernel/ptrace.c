/*
 * Copyright (c) 2017 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

#include <onyx/process.h>
#include <onyx/ptrace.h>

#include <uapi/user.h>

long sys_ptrace(long request, pid_t pid, void *addr, void *data, void *addr2)
{
    return -ENOSYS;
}
