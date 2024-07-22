/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _CARBON_PAIR_HPP
#define _CARBON_PAIR_HPP

#include <stddef.h>

#include <onyx/tuple_size.hpp>
#include <onyx/utility.hpp>

namespace cul
{

template <typename type1, typename type2>
class pair
{
public:
    using first_type = type1;
    using second_type = type2;
    type1 first;
    type2 second;

    constexpr pair(const type1& first, const type2& second) : first(first), second(second)
    {
    }
    template <typename U1, typename U2>
    constexpr pair(U1&& first, U2&& second)
        : first(cul::forward<U1>(first)), second(cul::forward<U2>(second))
    {
    }

    constexpr bool operator==(const pair<type1, type2>& rhs)
    {
        if (rhs.first == first && rhs.second == second)
            return true;
        return false;
    }

    constexpr bool operator!=(const pair<type1, type2>& rhs)
    {
        if (rhs.first != first || rhs.second != second)
            return true;
        return false;
    }
};

}; // namespace cul

namespace std
{

#if 0

template <typename... _Args>
struct tuple_size<cul::pair<_Args...>>
{
public:
	static constexpr size_t value = 2;
};

#endif
}; // namespace std

#endif
