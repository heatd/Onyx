/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_HANDLE_H
#define _ONYX_HANDLE_H

#include <onyx/file.h>

#include <uapi/handle.h>

namespace onx
{

namespace handle
{

class handleable
{
protected:
public:
    virtual ~handleable()
    {
    }

    virtual ssize_t query(void *ubuf, ssize_t len, unsigned long what, size_t *uhowmany, void *uarg)
    {
        return -EINVAL;
    }

    virtual void handle_ref() = 0;
    virtual void handle_unref() = 0;
};

file *create_file(handleable *object);

} // namespace handle

} // namespace onx

#endif
