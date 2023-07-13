/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_EXPECTED_HPP
#define _ONYX_EXPECTED_HPP

#include <assert.h>

#if defined __has_include
#if __has_include(<source_location>)
/* Unfortunately we need the compiler's magic for <source_location>, so we can't roll our own */
#include <source_location>
#define EXPECTED_HAS_SOURCE_LOCATION
#endif
#endif

#include <onyx/utility.hpp>

template <typename _Errortype>
class unexpected
{
private:
    _Errortype t;

public:
    constexpr unexpected(const _Errortype& val) : t{val}
    {
    }

    constexpr _Errortype& value()
    {
        return t;
    }
};

template <typename _Type, typename _ErrorType>
class expected
{
private:
    union {
        _Type t;
        _ErrorType e;
    };

    bool _has_value;

public:
    constexpr expected() : t{}, _has_value{true}
    {
    }
    constexpr expected(const _Type& t) : t{t}, _has_value{true}
    {
    }
    constexpr expected(const unexpected<_ErrorType>& e) : e{e.value()}, _has_value{false}
    {
    }
    constexpr expected(_Type&& type) : t{cul::move(type)}, _has_value{true}
    {
    }

    constexpr expected(expected<_Type, _ErrorType>&& rhs)
    {
        _has_value = rhs._has_value;
        if (_has_value)
            new (&t) _Type{cul::move(rhs.t)};
        else
            new (&e) _ErrorType{cul::move(rhs.e)};
    }

    constexpr expected(unexpected<_ErrorType>&& e) : e{cul::move(e.value())}, _has_value{false}
    {
    }

    constexpr expected<_Type, _ErrorType>& operator=(expected<_Type, _ErrorType>&& rhs)
    {
        if (_has_value == rhs._has_value)
        {
            // has_value == other has_value means that whatever we're assigning to
            // was already constructed, so just move
            if (rhs._has_value)
                t = cul::move(rhs.t);
            else
                e = cul::move(rhs.e);
        }
        else
        {
            // Destroy what was there before we construct a new thing
            if (!_has_value) [[unlikely]]
                e.~_ErrorType();
            else [[likely]]
                t.~_Type();

            if (rhs._has_value)
                new (&t) _Type{cul::move(rhs.t)};
            else
                new (&e) _ErrorType{cul::move(rhs.e)};
        }

        _has_value = rhs._has_value;
        return *this;
    }

    ~expected()
    {
        if (!_has_value) [[unlikely]]
            e.~_ErrorType();
        else [[likely]]
            t.~_Type();
    }

    constexpr bool has_value() const
    {
        return _has_value;
    }

    constexpr bool has_error() const
    {
        return !_has_value;
    }

#ifdef EXPECTED_HAS_SOURCE_LOCATION
    constexpr _Type&& unwrap(std::source_location loc = std::source_location::current())
    {
        if (!_has_value)
            panic("unwrap: Expected %p does not have a value, from %s:%u:%u::%s\n", this,
                  loc.file_name(), loc.line(), loc.column(), loc.function_name());
        return cul::move(t);
    }
#else
    constexpr _Type&& unwrap()
    {
        if (!_has_value)
            panic("unwrap: Expected %p does not have a value", this);
        return cul::move(t);
    }
#endif

    constexpr _Type&& value()
    {
        assert(has_value() == true);
        return cul::move(t);
    }

    constexpr _ErrorType& error()
    {
        assert(has_value() == false);
        return e;
    }

    constexpr operator bool() const
    {
        return has_value();
    }

    template <typename T>
    constexpr _Type value_or(T&& alt)
    {
        if (has_value()) [[likely]]
            return value();
        else
            return cul::forward<T>(alt);
    }

    template <typename Callable>
    expected<_Type, _ErrorType> then(const Callable& c)
    {
        if (_has_value)
            return c(*this);
        else
            return cul::move(*this);
    }

    template <typename OtherType, typename OtherError>
    expected<OtherType, OtherError> cast()
    {
        if (_has_value)
            return expected<OtherType, OtherError>(*this);
        else
            return unexpected<OtherError>(e);
    }

    template <typename OtherType, typename OtherError, typename TypeFilter>
    expected<OtherType, OtherError> cast(TypeFilter f)
    {
        if (_has_value)
            return expected<OtherType, OtherError>(f(value()));
        else
            return unexpected<OtherError>(e);
    }
};

#endif
