/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_TRACING_BUFFER_H
#define _ONYX_TRACING_BUFFER_H

#include <onyx/page.h>
#include <onyx/types.h>
#include <onyx/vm.h>

class tracing_buffer
{
    u8* buf_;
    size_t rd;
    size_t wr;
    size_t buflen;
    size_t mask;

    size_t overruns;

public:
    tracing_buffer(size_t len) : buflen{len}
    {
        buf_ =
            (u8*) vmalloc(vm_size_to_pages(len), VM_TYPE_REGULAR, VM_READ | VM_WRITE, GFP_KERNEL);
        rd = wr = 0;

        mask = len - 1;
    }

    ~tracing_buffer()
    {
        // TODO
    }

    bool full() const
    {
        return wr - rd == buflen;
    }

    bool empty() const
    {
        return wr == rd;
    }

    void read_no_consume(u8* buf, size_t len)
    {
        size_t i = 0;
        while (len--)
        {
            size_t j = (rd + i) & mask;
            buf[i++] = buf_[j];
        }
    }

    size_t read(u8* buf, size_t len);

    void discard_next_record();

    void write(const u8* buf, size_t len);
};

#endif
