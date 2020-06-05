/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_EXPECTED_HPP
#define _ONYX_EXPECTED_HPP

#include <assert.h>
#include <onyx/utility.hpp>

template <typename _Errortype>
class unexpected
{
private:
	_Errortype t;
public:
	constexpr unexpected(const _Errortype& val) : t{val} {}

	constexpr _Errortype& value()
	{
		return t;
	}
};

template <typename _Type, typename _ErrorType>
class expected
{
private:
	union
	{
		_Type t;
		_ErrorType e;
	};

	bool _has_value;
public:
	constexpr expected() : t{}, _has_value{true} {}
	constexpr expected(const _Type& t) : t{t}, _has_value{true} {}
	constexpr expected(const unexpected<_ErrorType>& e) : e{e.value()}, _has_value{false} {}
	constexpr expected(_Type&& t) : t{cul::move(t)}, _has_value{true} {}
	constexpr expected(unexpected<_ErrorType>&& e) : e{cul::move(e.value())}, _has_value{false} {}

	~expected()
	{
		if(!_has_value) [[unlikely]]
			e.~_ErrorType();
		else [[likely]]
			t.~_Type();
	}

    constexpr bool has_value() const
	{
		return _has_value;
	}

	constexpr _Type& value()
	{
		assert(has_value() == true);
		return t;
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
		if(has_value()) [[likely]]
			return value();
		else
			return cul::forward<T>(alt);
	}
};

#endif
