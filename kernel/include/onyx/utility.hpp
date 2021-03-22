/*
* Copyright (c) 2019, 2020, 2021 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_UTILTY_H
#define _CARBON_UTILTY_H

#include <onyx/integral_constant.h>
#include <stddef.h>

namespace cul
{

template <typename T>
struct remove_reference {typedef T type; };

template <typename T>
struct remove_reference<T&> { typedef T type; };

template <typename T>
struct remove_reference<T&&> { typedef T type; };

template <typename T>
typename remove_reference<T>::type&& move(T&& t)
{
	return static_cast<typename remove_reference<T>::type&& >(t);
}

template<typename _Type>
constexpr _Type&& forward(typename remove_reference<_Type>::type& t)
{
	return static_cast<_Type&&>(t);
}

template<typename _Type>
constexpr _Type&& forward(typename remove_reference<_Type>::type&& t)
{
	return static_cast<_Type&&>(t);
}

template <typename T>
void swap(T& a, T& b)
{
	T temp(move(a));
	a = move(b);
	b = move(temp);
}

template <typename Type>
Type min(Type t0, Type t1)
{
	return t0 > t1 ? t1 : t0;
}

template <typename Type>
Type max(Type t0, Type t1)
{
	return t0 < t1 ? t1 : t0;
}

template <typename T, typename U>
constexpr T align_up2(T number, U alignment)
{
	return (number + (alignment - 1)) & -alignment;
}

template <typename T, typename U>
constexpr T align_down2(T number, U alignment)
{
	return number & ~(alignment - 1);
}

template <typename Type, typename Type2>
Type2 clamp(Type t0, Type2 max)
{
	return t0 > max ? max : (Type2) t0;
}

#define CLASS_DISALLOW_MOVE(class_name) \
class_name& operator=(class_name&& rhs) = delete; \
class_name(class_name&& rhs) = delete;

#define CLASS_DISALLOW_COPY(class_name) \
class_name& operator=(const class_name& rhs) = delete; \
class_name(const class_name& rhs) = delete;

template <typename _Ty>
struct is_array : cul::false_type
{
};

template <typename _Ty>
struct is_array<_Ty[]> : cul::true_type
{
};

template <typename _Ty, size_t _N>
struct is_array<_Ty[_N]> : cul::true_type
{};

template <typename _Ty>
inline constexpr bool is_array_v = is_array<_Ty>::value;

}

#endif
