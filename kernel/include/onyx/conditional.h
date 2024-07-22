/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _CARBON_CONDITIONAL_H
#define _CARBON_CONDITIONAL_H

/* Implementation of std::conditional as described in
 * https://en.cppreference.com/w/cpp/types/conditional */
template <bool cond, typename T, typename F>
struct conditional
{
    typedef T type;
};

template <typename T, typename F>
struct conditional<false, T, F>
{
    typedef F type;
};

#endif