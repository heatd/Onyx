/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIType License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_SLICE_HPP
#define _ONYX_SLICE_HPP

#include <stddef.h>
#include <stdint.h>

#include <onyx/conditional.h>

namespace cul
{

constexpr size_t dynamic_extent = (size_t) -1;

template <typename Type, size_t length>
class slice_dynamic
{
protected:
    Type *ptr;
    /* Length in object count */
    size_t len;

public:
    slice_dynamic(Type *p, size_t l) : ptr{p}, len{l}
    {
    }
    constexpr slice_dynamic() : ptr(nullptr), len(0)
    {
    }

    ~slice_dynamic()
    {
    }

    size_t size() const
    {
        return len;
    }
};

template <typename Type, size_t length>
class slice_static
{
protected:
    Type *ptr;

public:
    slice_static(Type *p, size_t l) : ptr{p}
    {
    }
    constexpr slice_static() : ptr{nullptr}
    {
    }
    ~slice_static()
    {
    }

    constexpr size_t size() const
    {
        return length;
    }
};

template <typename Type, size_t length = dynamic_extent>
class slice : public conditional<length == dynamic_extent, slice_dynamic<Type, length>,
                                 slice_static<Type, length>>::type
{
private:
    using base_class = typename conditional<length == dynamic_extent, slice_dynamic<Type, length>,
                                            slice_static<Type, length>>::type;

public:
    template <typename IteratorType>
    slice(IteratorType t, size_t count) : base_class{t, count}
    {
    }

    template <typename IteratorType>
    slice(IteratorType start, IteratorType end) : base_class{start, end - start}
    {
    }

    constexpr slice() : base_class{}
    {
    }

    Type *data() const
    {
        return this->ptr;
    }

    Type &front() const
    {
        return *data();
    }

    Type &back() const
    {
        return *(data() + this->size() - 1);
    }

    Type &operator[](size_t idx) const
    {
        return *(data() + idx);
    }

    Type *begin()
    {
        return data();
    }

    Type *end()
    {
        return data() + this->size();
    }

    const Type *cbegin() const
    {
        return data();
    }

    const Type *cend() const
    {
        return data() + this->size();
    }

    size_t size_bytes()
    {
        return this->size() * sizeof(Type);
    }
};

template <typename Type, size_t length>
slice<const uint8_t, length> as_bytes(cul::slice<Type, length> &s)
{
    return slice<const uint8_t, length>{reinterpret_cast<const uint8_t *>(s.data()),
                                        s.size_bytes()};
}

template <typename Type, size_t length>
slice<const uint8_t, length> as_writable_bytes(cul::slice<Type, length> &s)
{
    return slice<uint8_t, length>{reinterpret_cast<uint8_t *>(s.data()), s.size_bytes()};
}

}; // namespace cul

#endif
