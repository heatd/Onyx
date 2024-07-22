/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_MEMORY_HPP
#define _ONYX_MEMORY_HPP

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

#include <onyx/enable_if.h>
#include <onyx/new.h>
#include <onyx/remove_extent.h>

#include <onyx/expected.hpp>
#include <onyx/utility.hpp>

static constexpr unsigned char _R__refc_was_make_shared = (1 << 0);

template <typename T>
class refcount
{
private:
    unsigned long ref;
    T* data;
    unsigned char flags;

public:
    refcount() : ref(1), data(nullptr)
    {
    }
    refcount(T* d) : ref(1), data(d)
    {
    }
    refcount(unsigned char flags) : ref(0), data{nullptr}, flags{flags}
    {
    }
    ~refcount()
    {
        if (data)
            delete data;
    }

    long get_ref(void)
    {
        return ref;
    }

    T* get_data(void)
    {
        return data;
    }

    void release(void)
    {
        /* 1 - 1 = 0! */
        if (__sync_fetch_and_sub(&ref, 1) == 1)
        {
            if (!(flags & _R__refc_was_make_shared)) [[unlikely]]
                delete data;
            else
                data->~T();

            data = nullptr;
            /* Commit sudoku */
            delete this;
        }
    }

    void refer(void)
    {
        __sync_fetch_and_add(&ref, 1);
    }

    void __set_data(T* d)
    {
        data = d;
    }

    void __set_refs(unsigned long refs)
    {
        ref = refs;
    }
};

typedef decltype(nullptr) nullptr_t;

template <typename T>
class shared_ptr
{
private:
    refcount<T>* ref;
    T* p;
    using element_type = remove_extent_t<T>;

    void __reset()
    {
        ref = nullptr;
        p = nullptr;
    }

    void assign_pointer_to_self(T* ptr)
    {
        if (ptr != nullptr) [[likely]]
            ref = new refcount<T>(ptr);
        else
            ref = nullptr;

        if (ref == nullptr) [[unlikely]]
            p = nullptr;
        else
            p = ptr;
    }

public:
    explicit shared_ptr() : ref(nullptr), p{nullptr}
    {
    }
    explicit shared_ptr(T* data)
    {
        assign_pointer_to_self(data);
    }

    shared_ptr(nullptr_t data)
    {
        assign_pointer_to_self(data);
    }

    void reset(T* ptr_ = nullptr)
    {
        if (ref) [[likely]]
        {
            ref->release();
            __reset();
        }

        if (ptr_) [[unlikely]]
        {
            assign_pointer_to_self(ptr_);
        }
    }

    refcount<T>* __get_refc() const
    {
        return ref;
    }

    void __set_refc(refcount<T>* r)
    {
        reset();
        r->refer();
        ref = r;
        p = r->get_data();
    }

    shared_ptr(const shared_ptr& ptr)
    {
        auto refc = ptr.__get_refc();
        if (refc)
            refc->refer();
        ref = refc;
        p = refc ? refc->get_data() : nullptr;
    }

    shared_ptr(shared_ptr&& ptr) : ref(ptr.ref), p(ptr.get_data())
    {
        ptr.__reset();
    }

    shared_ptr& operator=(shared_ptr&& ptr)
    {
        auto refc = ptr.__get_refc();

        if (ref == refc)
            goto ret;

        if (ref)
        {
            reset();
        }

        ref = ptr.__get_refc();
        p = ptr.get_data();
        ptr.__reset();

    ret:
        return *this;
    }

    shared_ptr& operator=(const shared_ptr& ptr)
    {
        auto refc = ptr.__get_refc();

        if (ref == refc)
            goto ret;

        if (ref)
        {
            reset();
        }

        ref = ptr.__get_refc();
        p = ptr.get_data();

        if (ref)
            ref->refer();

    ret:
        return *this;
    }

    bool operator==(const shared_ptr& p)
    {
        return (p.ref == ref);
    }

    bool operator==(const T* ptr)
    {
        if (!ref && !ptr)
            return true;
        else if (!ref)
            return false;

        return (ref->get_data() == ptr);
    }

    bool operator!=(const shared_ptr& p)
    {
        return !operator==(p);
    }

    bool operator!=(const T* ptr)
    {
        return !operator==(ptr);
    }

    element_type& operator[](size_t index)
    {
        return ref->data[index];
    }

    ~shared_ptr()
    {
        auto r = ref;
        ref = nullptr;
        p = nullptr;

        if (r)
            r->release();
    }

    T* get_data() const
    {
        return p;
    }

    T* get() const
    {
        return p;
    }

    T& operator*() const
    {
        return *get_data();
    }

    T* operator->() const
    {
        return get_data();
    }

    bool operator!() const
    {
        return get_data() == nullptr;
    }

    operator bool() const
    {
        return get_data() != nullptr;
    }
};

template <typename T>
class unique_ptr
{
private:
    T* p;
    using element_type = remove_extent_t<T>;

    void delete_mem()
    {
        if (p)
        {
            if constexpr (cul::is_array_v<T>)
                delete[] p;
            else
                delete p;
        }
    }

public:
    constexpr unique_ptr() : p(nullptr)
    {
    }

    typedef decltype(nullptr) nullptr_t;

    constexpr unique_ptr(nullptr_t data) : p(nullptr)
    {
    }

    constexpr explicit unique_ptr(T* data) : p(data)
    {
    }

    unique_ptr(const unique_ptr& ptr) = delete;

    T* release()
    {
        auto ret = p;
        p = nullptr;
        return ret;
    }

    void reset(T* new_ptr)
    {
        delete_mem();
        p = new_ptr;
    }

    template <typename Type>
    unique_ptr(unique_ptr<Type>&& ptr) : p(ptr.release())
    {
    }

    template <typename Type>
    unique_ptr& operator=(unique_ptr<Type>&& ptr)
    {
        reset(ptr.release());
        return *this;
    }

    unique_ptr& operator=(const unique_ptr& p) = delete;

    bool operator==(const unique_ptr& p) const
    {
        return (p == p.p);
    }

    bool operator==(const T* ptr) const
    {
        return (p == ptr);
    }

    bool operator!=(const unique_ptr& p) const
    {
        return !operator==(p);
    }

    bool operator!=(const T* ptr) const
    {
        return !operator==(ptr);
    }

    element_type& operator[](size_t index)
    {
        return p[index];
    }

    ~unique_ptr()
    {
        delete_mem();
    }

    T* get_data() const
    {
        return p;
    }

    T* get() const
    {
        return p;
    }

    T& operator*() const
    {
        return *get_data();
    }

    T* operator->() const
    {
        return get_data();
    }

    bool operator!()
    {
        return get_data() == nullptr;
    }

    operator bool()
    {
        return get_data() != nullptr;
    }

    expected<unique_ptr<T>, int> to_expected()
    {
        if (!p)
            return unexpected<int>{-ENOMEM};
        return cul::move(*this);
    }

    template <typename Type>
    expected<unique_ptr<Type>, int> to_expected()
    {
        if (!p)
            return unexpected<int>{-ENOMEM};
        return unique_ptr<Type>{this->release()};
    }

    template <typename OtherType>
    unique_ptr<OtherType> cast()
    {
        return unique_ptr<OtherType>{release()};
    }
};

template <typename T, class... Args>
shared_ptr<T> make_shared(Args&&... args)
{
    auto refc_part_size = cul::align_up2(sizeof(refcount<T>), alignof(T));
    char* buf = (char*) malloc(refc_part_size + sizeof(T));
    if (!buf)
        return nullptr;

    refcount<T>* refc = new (buf) refcount<T>(_R__refc_was_make_shared);
    T* data = new (buf + refc_part_size) T(cul::forward<Args>(args)...);
    refc->__set_data(data);

    shared_ptr<T> p(nullptr);
    p.__set_refc(refc);
    return p;
}

template <typename T, typename U>
shared_ptr<T> cast(const shared_ptr<U>& s)
{
    auto ref = s.__get_refc();
    shared_ptr<T> p{};
    p.__set_refc((refcount<T>*) ref);
    return p;
}

template <typename T, class... Args>
unique_ptr<T> make_unique(Args&&... args)
{
    T* data = new T(cul::forward<Args>(args)...);
    if (!data)
        return nullptr;

    unique_ptr<T> p(data);
    return p;
}

/* TODO: Calling this simply make_unique doesn't work because the overloads always point to regular
 * non-array make_unique. enable_if?
 */
template <typename T>
unique_ptr<T> make_unique_array(size_t n)
{
    T* data = new T[n]{};
    if (!data)
        return nullptr;

    unique_ptr<T> p(data);
    return p;
}

#endif
