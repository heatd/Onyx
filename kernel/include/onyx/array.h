/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_ARRAY_H
#define _CARBON_ARRAY_H

#include <stdio.h>
#include <onyx/panic.h>
#include <onyx/array_iterator.h>

/* Implements an std::array-like construct */

template <typename T, unsigned long nr_elem>
class array
{
private:

public:
	T data[nr_elem];

	constexpr T& operator[](unsigned long index)
	{
		if(index >= nr_elem)
			panic_bounds_check(this, false, index);
		return data[index];
	}

	constexpr const T& operator[](unsigned long index) const
	{
		if(index >= nr_elem)
			panic_bounds_check(this, false, index);
		return (const T&) data[index];
	}

	unsigned long size() const
	{
		return nr_elem;
	}

	T* begin()
	{
		return data;
	}

	T* end()
	{
		return data + nr_elem;
	}

	const T* cbegin() const
	{
		return data;
	}

	const T* cend() const
	{
		return data + nr_elem;
	}
};

template <typename T, unsigned long nr_elem>
constexpr bool operator==(const array<T, nr_elem>& lhs, const array<T, nr_elem>& rhs)
{
	for(auto i = 0UL; i < nr_elem; i++)
	{
		if(lhs.data[i] != rhs.data[i])
			return false;
	}

	return true;
}

template <typename T, unsigned long nr_elem>
constexpr bool operator!=(const array<T, nr_elem>& lhs, const array<T, nr_elem>& rhs)
{
	return !(lhs == rhs);
}

#endif