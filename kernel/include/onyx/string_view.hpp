/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_STRING_VIEW_HPP
#define _ONYX_STRING_VIEW_HPP

#include <stdint.h>
#include <stddef.h>
#include <string.h>
namespace std
{

template <typename _CharT>
class basic_string_view
{
public:
	using const_pointer = const _CharT*;
	using value_type = _CharT;
	using pointer = _CharT*;
	using const_iterator = const_pointer;
	using iterator = const_pointer;
	using size_type = size_t;
	static constexpr size_type npos = size_type(-1);
private:
	const_pointer data_;
	size_type length_;
public:
	constexpr basic_string_view(const _CharT *str, size_type length) : data_{str}, length_{length} {}

	constexpr basic_string_view() : data_{}, length_{} {}

	constexpr const_pointer data() const
	{
		return data_;
	}

	constexpr size_type length() const
	{
		return length_;
	}

	constexpr size_type size() const
	{
		return length_;
	}

	constexpr bool empty() const
	{
		return length_ == 0;
	}

	constexpr const _CharT& operator[](size_type idx) const
	{
		return data_[idx];
	}

	constexpr basic_string_view<_CharT> substr(size_type pos = 0, size_type count = npos) const
	{
		return {data_ + pos, count};
	}

	constexpr size_type find(_CharT c, size_type pos = 0) const
	{
		for(size_type i = pos; i < length_; i++)
		{
			if(data_[i] == c)
				return i;
		}

		return npos;
	}

	constexpr size_type find(const _CharT *s, size_type pos = 0) const
	{
		for(size_type i = pos; i < length_; i++)
		{
			for(auto _s = s; *_s; ++_s)
			{
				if(data_[i] == *_s)
					return i;
			}
		}

		return npos;
	}

	constexpr size_type find_first_not_of(_CharT c, size_type pos = 0) const
	{
		for(size_type i = pos; i < length_; i++)
		{
			if(data_[i] != c)
				return i;
		}

		return npos;
	}

	constexpr size_type find_first_not_of(const _CharT *s, size_type pos = 0) const
	{
		for(size_type i = pos; i < length_; i++)
		{
			for(auto _s = s; *_s; ++_s)
			{
				if(data_[i] != *_s)
					return i;
			}
		}

		return npos;
	}

	constexpr int compare(const std::basic_string_view<_CharT> other) const
	{
		/* This should do what we want: return negative if this len < other len,
		 * positive if other len < this len.
		 */
		auto to_cmp = other.length_ < length_ ? other.length_ : length_;
		
		const auto other_data = other.data();

		for(size_type i = 0; i < to_cmp; i++)
		{
			if(data_[i] != other_data[i])
				return data_[i] - other_data[i];
		}

		return length_ - other.length_;
	}

	constexpr int compare(const_pointer s) const
	{
		return compare(std::basic_string_view<_CharT>(s, strlen(s)));
	}
};


using string_view = basic_string_view<char>;

}

#endif
