/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wunused-parameter"
int open(const char *path, int flags)
{
    return 0;
}
int close(int fd)
{
    return 0;
}
ssize_t read(int fd, void *buf, size_t count)
{
    return 0;
}
ssize_t write(int fd, const void *buf, size_t count)
{
    return 0;
}
off_t lseek(int fd, off_t offset, int whence)
{
    return 0;
}
int isatty(int fildes)
{
    return 0;
}
int ioctl(int fd, int op, ...)
{
    return 0;
}
#pragma GCC pop_options