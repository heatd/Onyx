/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _KERNEL_USER_H
#define _KERNEL_USER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char *strcpy_from_user(const char *user);
size_t strlen_user(const char *user);

long get_user32(unsigned int *uaddr, unsigned int *dest);
long get_user64(unsigned long *uaddr, unsigned long *dest);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <onyx/expected.hpp>

class user_string
{
private:
    char *buf;

public:
    user_string() : buf{nullptr}
    {
    }

    user_string(const user_string &rhs) = delete;
    user_string &operator=(const user_string &rhs) = delete;

    user_string(user_string &&rhs) = default;
    user_string &operator=(user_string &&rhs) = default;

    ~user_string()
    {
        free((void *) buf);
    }

    expected<char *, int> from_user(const char *ustring)
    {
        auto ret = buf = strcpy_from_user(ustring);
        if (!ret) [[unlikely]]
            return unexpected<int>{-errno};
        return ret;
    }

    char *data() const
    {
        return buf;
    }

    char *release()
    {
        auto r = buf;
        buf = nullptr;
        return r;
    }

    char &operator[](size_t index) const
    {
        return buf[index];
    }

    /* We don't provide an implicit convertion to char * because that would be unsafe */
};

#endif

#endif
