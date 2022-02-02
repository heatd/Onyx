/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_INTEGRAL_CONSTANT_H
#define _ONYX_INTEGRAL_CONSTANT_H

namespace cul
{

template <typename _Ty, _Ty _Val>
struct integral_constant
{
    using value_type = _Ty;
    using type = integral_constant;

    static constexpr _Ty value = _Val;

    constexpr operator value_type()
    {
        return value;
    }

    constexpr value_type operator()()
    {
        return value;
    }
};

template <bool _Val>
using bool_constant = integral_constant<bool, _Val>;

using false_type = bool_constant<false>;
using true_type = bool_constant<true>;

} // namespace cul
#endif
