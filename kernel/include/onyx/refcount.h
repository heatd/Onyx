/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _CARBON_REFCOUNT_H
#define _CARBON_REFCOUNT_H

#include <assert.h>

// Note: CONFIG_REFCOUNT_ENABLE_TRACE has significant overhead (branch on every refcount op), so
// only enable it if really needed
#ifdef CONFIG_REFCOUNT_ENABLE_TRACE
#include <onyx/gen/trace_refcount.h>

#define TRACE_REFC_REF                    \
    if (trace_refcountable_ref_enabled()) \
    trace_refcountable_ref((unsigned long) this)

#define TRACE_REFC_UNREF                    \
    if (trace_refcountable_unref_enabled()) \
    trace_refcountable_unref((unsigned long) this)

#define REFCOUNT_INLINE
#else

#define TRACE_REFC_REF
#define TRACE_REFC_UNREF

#define REFCOUNT_INLINE [[gnu::always_inline]]
#endif

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

    REFCOUNT_INLINE unsigned long ref()
    {
        TRACE_REFC_REF;
        return __refcount.add_fetch(1, mem_order::acquire);
    }

    REFCOUNT_INLINE unsigned long refer_multiple(unsigned long n)
    {
        TRACE_REFC_REF;
        return __refcount.add_fetch(n, mem_order::acquire);
    }

    REFCOUNT_INLINE bool unref()
    {
        TRACE_REFC_UNREF;
        bool was_deleted = false;
        if (__refcount.sub_fetch(1, mem_order::release) == 0)
        {
            was_deleted = true;
            delete this;
        }

        return was_deleted;
    }

    REFCOUNT_INLINE bool unref_multiple(unsigned long n)
    {
        TRACE_REFC_UNREF;
        bool was_deleted = false;
        if (__refcount.sub_fetch(n, mem_order::release) == 0)
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

public:
    void ref()
    {
        if (!p)
            return;
        p->ref();
    }

    void unref()
    {
        if (!p)
            return;
        p->unref();
    }

    void disable()
    {
        p = nullptr;
    }

    T* release()
    {
        auto ret = p;
        p = nullptr;
        return ret;
    }

    explicit ref_guard(T* p) : p(p)
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

    ref_guard(const ref_guard& r) : p(r.p)
    {
        if (p)
            p->ref();
    }

    ref_guard(ref_guard&& r) : p(r.p)
    {
        r.p = nullptr;
    }

    ref_guard& operator=(const ref_guard& r)
    {
        const auto p0 = p;
        p = r.p;
        p->ref();
        if (p0)
            p0->unref();

        return *this;
    }

    ref_guard& operator=(ref_guard&& r)
    {
        const auto p0 = p;
        p = r.p;
        r.p = nullptr;
        if (p0)
            p0->unref();

        return *this;
    }

    ~ref_guard()
    {
        if (p)
            p->unref();
    }

    template <typename OtherType>
    ref_guard<OtherType> cast()
    {
        return ref_guard<OtherType>{release()};
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
