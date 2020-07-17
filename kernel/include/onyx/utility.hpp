/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_UTILTY_H
#define _CARBON_UTILTY_H

namespace cul
{

template <typename T>
struct remove_reference {typedef T type; };

template <typename T>
struct remove_reference<T&> { typedef T type; };

template <typename T>
struct remove_reference<T&&> { typedef T type; };

template <typename T>
typename remove_reference<T>::type move(T&& t)
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

}

#endif
