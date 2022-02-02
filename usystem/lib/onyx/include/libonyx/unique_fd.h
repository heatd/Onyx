/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _LIBONYX_UNIQUEFD_H
#define _LIBONYX_UNIQUEFD_H

#include <unistd.h>

namespace onx
{

class unique_fd
{
private:
    int fd;

public:
    constexpr unique_fd() : fd{-1}
    {
    }

    constexpr unique_fd(int fd) : fd{fd}
    {
    }

    ~unique_fd()
    {
        if (fd != -1)
            ::close(fd);
    }

    constexpr unique_fd(unique_fd&& f) noexcept : fd{f.release()}
    {
    }

    unique_fd& operator=(unique_fd&& f) noexcept
    {
        reset(f.release());
        return *this;
    }

    // Delete the copy ctor/operator

    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;

    constexpr int release()
    {
        int to_ret = fd;
        fd = -1;
        return to_ret;
    }

    void reset(int new_fd) noexcept
    {
        if (fd != -1)
            ::close(fd);
        fd = new_fd;
    }

    constexpr bool valid() const
    {
        return fd != -1;
    }

    constexpr operator bool() const
    {
        return valid();
    }

    int get() const
    {
        return fd;
    }
};

} // namespace onx

#endif
