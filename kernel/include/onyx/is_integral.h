/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _CARBON_IS_INTEGRAL_H
#define _CARBON_IS_INTEGRAL_H

/* I think this implementation should work?  */
template <typename T>
struct is_integral
{
    constexpr static bool value = false;
};

template <>
struct is_integral<bool>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const bool>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<char>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<unsigned char>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const char>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const unsigned char>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<short>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<unsigned short>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const short>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const unsigned short>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<int>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<unsigned int>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const int>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const unsigned int>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<long>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<unsigned long>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const long>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const unsigned long>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<long long>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<unsigned long long>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const long long>
{
    constexpr static bool value = true;
};

template <>
struct is_integral<const unsigned long long>
{
    constexpr static bool value = true;
};

template <typename T>
inline constexpr bool is_integral_v = is_integral<T>::value;

#endif