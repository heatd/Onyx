/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _CARBON_ENABLE_IF_H
#define _CARBON_ENABLE_IF_H

/* Implementation of std::enable_if as described in
 * https://en.cppreference.com/w/cpp/types/enable_if */

template <bool B, class T = void>
struct enable_if
{
};

template <class T>
struct enable_if<true, T>
{
    typedef T type;
};

#endif