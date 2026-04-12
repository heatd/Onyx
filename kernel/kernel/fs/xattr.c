/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stddef.h>

#include <onyx/types.h>

#include <uapi/errno.h>

/* Stub for python... */
ssize_t sys_listxattr(const char *path, char *list, size_t size)
{
    return -ENOTSUP;
}

ssize_t sys_llistxattr(const char *path, char *list, size_t size)
{
    return -ENOTSUP;
}

int sys_setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
    return -ENOTSUP;
}

int sys_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
    return -ENOTSUP;
}

int sys_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
{
    return -ENOTSUP;
}

ssize_t sys_getxattr(const char *path, const char *name, void *value, size_t size)
{
    return -ENOTSUP;
}

ssize_t sys_lgetxattr(const char *path, const char *name, void *value, size_t size)
{
    return -ENOTSUP;
}

ssize_t sys_fgetxattr(int fd, const char *name, void *value, size_t size)
{
    return -ENOTSUP;
}

int sys_removexattr(const char *path, const char *name)
{
    return -ENOTSUP;
}

int sys_lremovexattr(const char *path, const char *name)
{
    return -ENOTSUP;
}

int sys_fremovexattr(int fd, const char *name)
{
    return -ENOTSUP;
}
