/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _CARBON_REMOVE_EXTENT_H
#define _CARBON_REMOVE_EXTENT_H

#include <stddef.h>

template <typename T>
struct remove_extent
{
    typedef T type;
};

template <typename T>
struct remove_extent<T[]>
{
    typedef T type;
};

template <typename T>
struct remove_extent<T*>
{
    typedef T type;
};

template <typename T, size_t n>
struct remove_extent<T[n]>
{
    typedef T type;
};

template <typename T>
using remove_extent_t = typename remove_extent<T>::type;

#endif