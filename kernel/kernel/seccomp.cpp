/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>

#include <uapi/seccomp.h>

int sys_seccomp(unsigned int op, unsigned int flags, void *args)
{
    return -ENOSYS;
}
