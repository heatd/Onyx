/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_PAGE_IOV_H
#define _ONYX_PAGE_IOV_H

#include <assert.h>

#include <onyx/page.h>
#include <onyx/panic.h>

struct page_iov_iter;

struct page_iov
{
    struct page *page;
    unsigned int length;
    unsigned int page_off;

#ifdef __cplusplus
    page_iov_iter to_iter(unsigned int off = 0);

    void reset()
    {
        page = nullptr;
        length = page_off = (unsigned int) -1;
    }
#endif
};

#ifdef __cplusplus

struct page_iov_iter
{
    page_iov *v;
    unsigned int offset;

    page_iov_iter(page_iov *v, unsigned int offset) : v{v}, offset{offset}
    {
        assert(offset < v->length);
    }

    page_iov_iter() : v{nullptr}, offset{0}
    {
    }

    void increment(unsigned int bytes)
    {
        offset += bytes;
    }

    int length() const
    {
        return v->length - offset;
    }

    page_iov_iter &operator++()
    {
        v++;
        offset = 0;
        return *this;
    }

    page_iov_iter operator++(int)
    {
        page_iov_iter copy(*this);
        ++(*this);
        return copy;
    }

    bool valid() const
    {
        return !v || !v->page;
    }

    template <typename Type>
    Type *to_pointer()
    {
        return (Type *) ((unsigned long) PAGE_TO_VIRT(v->page) + v->page_off + offset);
    }
};

inline page_iov_iter page_iov::to_iter(unsigned int off)
{
    return {this, off};
}

#endif

#endif
