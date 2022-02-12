/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wunused-parameter"
ssize_t readv(int fd, const struct iovec *v, int veccount)
{
    return -1;
}
ssize_t writev(int fd, const struct iovec *v, int veccount)
{
    return -1;
}
ssize_t preadv(int fd, const struct iovec *v, int veccount, off_t offset)
{
    return -1;
}
ssize_t pwritev(int fd, const struct iovec *v, int veccount, off_t offset)
{
    return -1;
}
#pragma GCC pop_options
