/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_TUPLE_HPP
#define _ONYX_TUPLE_HPP

#include <stddef.h>

#include <onyx/tuple_size.hpp>
namespace std
{

template <size_t index, typename Type, typename... Args>
struct _Tuple_elem
{
    using type = Type;
    Type element;
    _Tuple_elem(Type t) : element{t}
    {
    }

    _Tuple_elem() : element{}
    {
    }
};

template <size_t index, typename Type, typename Next, typename... Args>
struct _Tuple_elem<index, Type, Next, Args...> : public _Tuple_elem<index + 1, Next, Args...>
{
    using type = Type;
    Type element;

    template <typename... _Args>
    _Tuple_elem(Type t, _Args&&... args)
        : _Tuple_elem<index + 1, Next, Args...>{args...}, element(t)
    {
    }

    _Tuple_elem() : element{}
    {
    }
};

template <typename... Args>
struct tuple : public _Tuple_elem<0, Args...>
{
public:
    tuple(Args&&... args) : _Tuple_elem<0, Args...>{args...}
    {
    }

    tuple(Args&... args) : _Tuple_elem<0, Args...>{args...}
    {
    }

    tuple()
    {
    }
};

template <>
class tuple<>
{
};

/* I'm confused, and this should all be fixed. */

template <size_t i, typename head, typename... tail>
constexpr const head& get_helper(const _Tuple_elem<i, head, tail...>& tuple)
{
    return tuple.element;
}

template <size_t i, typename head, typename... tail>
constexpr const head& get(const tuple<head, tail...>& tuple)
{
    return get_helper<i>(tuple);
}

template <size_t i, typename head, typename... tail>
constexpr head& get(tuple<head, tail...>& tuple)
{
    return get_helper<i>(tuple);
}

template <size_t i, typename head, typename... tail>
constexpr head&& get(tuple<head, tail...>&& tuple)
{
    return cul::forward<head&&>(get<i>(tuple));
}

template <typename... Args>
struct tuple_size<tuple<Args...>>
{
public:
    /* Thankfully sizeof... does the trick */
    static constexpr size_t value = sizeof...(Args);
};

template <size_t i, typename Type>
struct tuple_element;

template <size_t i, typename Head, typename... Tail>
struct tuple_element<i, std::tuple<Head, Tail...>> : std::tuple_element<i - 1, std::tuple<Tail...>>
{
};

template <typename Head, typename... Tail>
struct tuple_element<0, std::tuple<Head, Tail...>>
{
    typedef Head type;
};

}; // namespace std

#endif
