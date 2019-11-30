/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_ARRAY_ITERATOR_H
#define _CARBON_ARRAY_ITERATOR_H

template <typename T>
class array_iterator
{
private:
	T* elem;
public:
	array_iterator() : elem(nullptr)
	{}

	array_iterator(T* elem)
	{
		this->elem = elem;
	}

	array_iterator<T>& operator++()
	{
		elem++;
		return *this;
	}

	array_iterator<T> operator++(int)
	{
		array_iterator<T> copy(*this);
		++(*this);
		return copy;
	}

	T& operator*()
	{
		return *elem;
	}

	bool operator==(const array_iterator<T>& a)
	{
		return elem == a.elem;
	}

	bool operator!=(const array_iterator<T>& a)
	{
		return elem != a.elem;
	}
};

template <typename T>
class const_array_iterator
{
private:
	array_iterator<T> it;
public:
	const_array_iterator(T *p) : it(p)
	{
	}
	
	const_array_iterator<T>& operator++()
	{
		it++;
		return *this;
	}

	const_array_iterator<T> operator++(int)
	{
		const_array_iterator<T> copy(*this);
		++(*this);
		return copy;
	}

	const T& operator*()
	{
		return *it;
	}

	bool operator==(const const_array_iterator<T>& rhs)
	{
		return it == rhs.it;
	}

	bool operator!=(const const_array_iterator<T>& rhs)
	{
		return it != rhs.it;
	}
};

#endif