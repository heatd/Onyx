/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/types.h>

int sys_mlock(const void *addr, size_t len)
{
    return 0;
}

int sys_munlock(const void *addr, size_t len)
{
    return 0;
}

int sys_mlockall(int flags)
{
    return 0;
}

int sys_munlockall(void)
{
    return 0;
}
