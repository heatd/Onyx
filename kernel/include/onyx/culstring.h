/*
 * Copyright (c) 2021 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_STRING_H
#define _ONYX_STRING_H

#include <stddef.h>
#include <stdlib.h>

#include <onyx/string_view.hpp>
#include <onyx/utility.hpp>

namespace cul
{

template <typename _Ty>
class basic_string
{
private:
    _Ty* data_;
    size_t length_{0};

    // TODO: Kind-of-broken math for non 1-byte types (i.e UCS-32 strings get a huge structure)
    static constexpr size_t inline_length = sizeof(size_t) + 8;
    static constexpr size_t inline_capacity = inline_length - 1;

    union {
        size_t capacity_{0};
        _Ty inline_data[inline_length];
    };

    bool is_small() const
    {
        return length_ < inline_length;
    }

    bool try_realloc_data(size_t new_cap)
    {
        // If we were using inline storage, allocate dynamic storage
        if (data_ == (_Ty*) &inline_data)
        {
            auto new_data = malloc(new_cap * sizeof(_Ty));
            if (!new_data)
                return false;
            memcpy(new_data, inline_data, inline_length);
            data_ = (_Ty*) new_data;
            return true;
        }

        if (capacity_ >= new_cap)
            return true;

        auto new_data = realloc(data_, new_cap * sizeof(_Ty));
        if (!new_data)
            return false;

        data_ = (_Ty*) new_data;
        capacity_ = new_cap;

        return true;
    }

    bool grow(size_t new_size)
    {
        if (new_size < inline_length)
        {
            // Easy.
            // It's assumed that new_size won't overflow and cause it to go haywire.
            // TODO: Should we assume that?
            data_ = inline_data;
            return true;
        }
        else
        {
            auto new_cap = cul::align_up2(new_size + 1, 2);

            if (!try_realloc_data(new_cap))
                return false;
        }

        return true;
    }

    void internal_construct(const std::basic_string_view<_Ty>& sv)
    {
        length_ = sv.length();

        if (!grow(length_))
            return;

        memcpy(data_, sv.data(), length_);
        data_[length_] = '\0';
    }

public:
    using iterator = _Ty*;
    using const_iterator = const _Ty*;
    using value_type = _Ty;
    using size_type = size_t;

    constexpr basic_string() : data_{inline_data}
    {
    }

    ~basic_string()
    {
        clear();
    }

    basic_string(const char* s) : data_{nullptr}
    {
        internal_construct({s, strlen(s)});
    }

    explicit basic_string(const char* s, size_t strlength) : data_{nullptr}
    {
        internal_construct({s, strlength});
    }

    explicit basic_string(const std::basic_string_view<_Ty>& sv)
        : data_{nullptr}, length_{}, capacity_{}
    {
        internal_construct(sv);
    }

    basic_string(basic_string&& rhs)
    {
        if (rhs.is_small())
        {
            data_ = inline_data;
            length_ = rhs.length_;
            memcpy(inline_data, rhs.inline_data, length_ + 1);
        }
        else
        {
            data_ = rhs.data_;
            length_ = rhs.length_;
            capacity_ = rhs.capacity_;

            rhs.data_ = nullptr;
            rhs.length_ = 0;
            rhs.capacity_ = 0;
        }
    }

    basic_string& operator=(basic_string&& rhs)
    {
        if (this == &rhs)
            return *this;

        if (!empty())
            clear();

        if (rhs.is_small())
        {
            data_ = inline_data;
            length_ = rhs.length_;
            memcpy(inline_data, rhs.inline_data, length_ + 1);
        }
        else
        {
            data_ = rhs.data_;
            length_ = rhs.length_;
            capacity_ = rhs.capacity_;

            rhs.data_ = nullptr;
            rhs.length_ = 0;
            rhs.capacity_ = 0;
        }

        return *this;
    }

    basic_string(const basic_string& rhs)
    {
        if (rhs.is_small())
        {
            data_ = inline_data;
            length_ = rhs.length_;
            memcpy(inline_data, rhs.inline_data, length_ + 1);
        }
        else
        {
            data_ = nullptr;
            length_ = 0;
            capacity_ = 0;

            if (!grow(rhs.length()))
                return;

            length_ = rhs.length();

            memcpy(data_, rhs.data(), length_);
            data_[length_] = '\0';
        }
    }

    basic_string& operator=(const basic_string& rhs)
    {
        if (this == &rhs)
            return *this;

        if (!empty())
            clear();

        if (rhs.is_small())
        {
            data_ = inline_data;
            length_ = rhs.length_;
            memcpy(inline_data, rhs.inline_data, length_ + 1);
        }
        else
        {
            if (!grow(rhs.length()))
                return *this;

            length_ = rhs.length();

            memcpy(data_, rhs.data(), length_);
            data_[length_] = '\0';
        }

        return *this;
    }

    void clear()
    {
        if (!is_small()) [[unlikely]]
        {
            free((void*) data_);
            data_ = nullptr;
            capacity_ = 0;
        }

        length_ = 0;
    }

    size_t size() const
    {
        return length_;
    }

    size_t length() const
    {
        return length_;
    }

    size_t capacity() const
    {
        if (is_small()) [[likely]]
            return inline_capacity;
        else
            return capacity_;
    }

    value_type* data()
    {
        return data_;
    }

    const value_type* data() const
    {
        return data_;
    }

    value_type* c_str()
    {
        return data_;
    }

    const value_type* c_str() const
    {
        return data_;
    }

    operator std::basic_string_view<_Ty>() const
    {
        return {data_, length_};
    }

    [[nodiscard]] bool empty() const
    {
        return length_ == 0;
    }

    operator bool() const
    {
        return !empty();
    }

    bool append(const std::basic_string_view<_Ty>& sv)
    {
        auto len = length();
        auto new_size = len + sv.length();

        if (!grow(new_size))
            return false;

        memcpy(data_ + len, sv.data(), sv.length());
        // Re-null terminate the string
        data_[len + sv.length()] = '\0';
        length_ = len + sv.length();

        return true;
    }

    constexpr const _Ty& operator[](size_type idx) const
    {
        return data_[idx];
    }

    constexpr iterator begin()
    {
        return data_;
    }

    constexpr iterator end()
    {
        return data_ + length();
    }

    constexpr const_iterator begin() const
    {
        return data_;
    }

    constexpr const_iterator end() const
    {
        return data_ + length();
    }

    constexpr const_iterator cbegin() const
    {
        return data_;
    }

    constexpr const_iterator cend() const
    {
        return data_ + length();
    }

    size_type rfind(_Ty c, size_type pos = std::basic_string_view<_Ty>::npos)
    {
        return std::basic_string_view<_Ty>(*this).rfind(c, pos);
    }

    bool operator==(const char* s) const
    {
        return std::basic_string_view<_Ty>(s).compare(*this) == 0;
    }

    bool operator==(basic_string<_Ty> s) const
    {
        return std::basic_string_view<_Ty>(s).compare(*this) == 0;
    }
};

using string = basic_string<char>;

} // namespace cul

#endif
