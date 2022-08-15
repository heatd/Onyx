/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _CARBON_REFCOUNT_H
#define _CARBON_REFCOUNT_H

#include <assert.h>

#include <onyx/atomic.hpp>
#include <onyx/deleter.hpp>

#define REFCOUNT_DEBUG
class refcountable
{
public:
    atomic<unsigned long> __refcount;

    /* Note: refcountable() defaults to a refcount of 1 */
    constexpr refcountable() : __refcount(1)
    {
    }
    constexpr refcountable(unsigned long init) : __refcount(init)
    {
    }

    virtual ~refcountable()
    {
#ifdef REFCOUNT_DEBUG
        assert(__refcount < 2);
#endif
    }

    unsigned long ref()
    {
        return ++__refcount;
    }

    unsigned long refer_multiple(unsigned long n)
    {
        return __refcount.add_fetch(n);
    }

    bool unref()
    {
        bool was_deleted = false;
        if (--__refcount == 0)
        {
            was_deleted = true;
            delete this;
        }

        return was_deleted;
    }

    bool unref_multiple(unsigned long n)
    {
        bool was_deleted = false;
        if (__refcount.sub_fetch(n) == 0)
        {
            was_deleted = true;
            delete this;
        }

        return was_deleted;
    }

    unsigned long __get_refcount() const
    {
        return __refcount.load();
    }

    bool is_ghost_object() const
    {
        return __get_refcount() == 0;
    }
};

template <typename T>
class ref_guard
{
private:
    T* p;
    atomic<unsigned long> refed_counter;

public:
    void ref()
    {
        if (!p)
            return;
        p->ref();
        refed_counter++;
    }

    void unref()
    {
        if (!p)
            return;
        p->unref();
        refed_counter--;
    }

    void unref_everything()
    {
        if (!p)
            return;
        p->unref_multiple(refed_counter);
    }

    void disable()
    {
        refed_counter = 0;
        p = nullptr;
    }

    explicit ref_guard(T* p) : p(p), refed_counter{1}
    {
    }

    ref_guard() : p{nullptr}
    {
    }

    operator bool()
    {
        return p != nullptr;
    }

    T* operator->() const
    {
        return p;
    }

    T* get() const
    {
        return p;
    }

    T& operator*() const
    {
        return *p;
    }

    ref_guard(const ref_guard& r) : p(r.p), refed_counter(r.refed_counter)
    {
        if (!p)
            return;
        p->refer_multiple(refed_counter);
    }

    ref_guard(ref_guard&& r) : p(r.p), refed_counter(r.refed_counter)
    {
        r.p = nullptr;
        r.refed_counter = 0;
    }

    ref_guard& operator=(const ref_guard& r)
    {
        const auto p0 = p;
        const auto og_refed = refed_counter;
        p = r.p;
        refed_counter = r.refed_counter;
        p->refer_multiple(refed_counter);
        if (p0)
            p0->unref_multiple(og_refed);

        return *this;
    }

    ref_guard& operator=(ref_guard&& r)
    {
        const auto p0 = p;
        const auto og_refed = refed_counter;
        p = r.p;
        refed_counter = r.refed_counter;
        r.p = nullptr;
        r.refed_counter = 0;
        if (p0)
            p0->unref_multiple(og_refed);

        return *this;
    }

    ~ref_guard()
    {
        unref_everything();
    }
};

template <typename T, class... Args>
ref_guard<T> make_refc(Args&&... args)
{
    T* data = new T(args...);
    if (!data)
        return ref_guard<T>{nullptr};

    ref_guard<T> p(data);
    return p;
}

#endif
