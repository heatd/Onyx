/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_VECTOR_H
#define _CARBON_VECTOR_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/array_iterator.h>
#include <onyx/panic.h>
#include <onyx/new.h>
#include <onyx/utility.hpp>

namespace cul
{

template <typename T>
class vector
{
private:
	T *data;
	unsigned long buffer_size;
	unsigned long nr_elems;
	unsigned long log;

	void setup_expansion(size_t new_nr_elems)
	{
		for(size_t i = nr_elems; i < new_nr_elems; i++)
		{
			new (data + i) T{};
		}
	}

	bool expand_vec()
	{
		size_t new_buf_elems = 1 << log;
		size_t new_buffer_size = new_buf_elems * sizeof(T);
		T *new_data = reinterpret_cast<T*>(realloc((void *) data,
						   new_buffer_size));
		if(!new_data)
			return false;
		log++;
		data = new_data;
		setup_expansion(new_buf_elems);
		buffer_size = new_buf_elems;
		return true;
	}

	void duplicate_vector_data(const vector& rhs)
	{
		data = malloc(buffer_size * sizeof(T));
		assert(data != nullptr);
		
		for(size_t i = 0; i < nr_elems; i++)
		{
			data[i] = rhs.data[i];
		}
	}

public:
	constexpr vector() : data{nullptr}, buffer_size{0}, nr_elems{0}, log{0}
	{

	}

	vector(const vector& rhs)
	{
		this->buffer_size = rhs.buffer_size;
		this->log = rhs.log;
		this->nr_elems = rhs.nr_elems;

		duplicate_vector_data(rhs);
	}

	vector& operator=(const vector& rhs)
	{
		clear();
		this->buffer_size = rhs.buffer_size;
		this->log = rhs.log;
		this->nr_elems = rhs.nr_elems;

		duplicate_vector_data(rhs);

		return *this;
	}

	vector(vector&& rhs)
	{
		this->buffer_size = rhs.buffer_size;
		this->log = rhs.log;
		this->nr_elems = rhs.nr_elems;
		this->data = rhs.data;

		rhs.buffer_size = 0;
		rhs.log = 0;
		rhs.nr_elems = 0;
		rhs.data = nullptr;
	}

	vector& operator=(vector&& rhs)
	{
		clear();
		this->buffer_size = rhs.buffer_size;
		this->log = rhs.log;
		this->nr_elems = rhs.nr_elems;
		this->data = rhs.data;

		rhs.buffer_size = 0;
		rhs.log = 0;
		rhs.nr_elems = 0;
		rhs.data = nullptr;

		return *this;
	}

	bool alloc_buf(size_t size)
	{
		auto old_log = log;
		auto _log = ilog2(size);
		if(size & ((1 << _log) - 1))
			_log++;
		
		assert(nr_elems <= size);

		log = _log;
		if(!expand_vec())
		{
			/* Revert */
			log = old_log;
			return false;
		}

		return true;
	}

	bool push_back(const T& obj)
	{
		if(nr_elems >= buffer_size)
		{
			if(!expand_vec())
				return false;
		}

		data[nr_elems++] = obj;

		return true;
	}

	bool push_back(T&& obj)
	{
		if(nr_elems >= buffer_size)
		{
			if(!expand_vec())
				return false;
		}

		data[nr_elems++] = cul::move(obj);

		return true;
	}

	void clear()
	{
		if(!data)
			return;
		for(unsigned long i = 0; i < nr_elems; i++)
		{
			T& ref = data[i];
			ref.~T();
		}

		free(data);
		data = nullptr;
		buffer_size = 0;
		nr_elems = 0;
		log = 0;
	}

	~vector()
	{
		if(data)
		{
			clear();
		}
	}

	T& operator[](unsigned long idx)
	{
		if(idx >= nr_elems)
		{
			panic_bounds_check(this, true, idx);
		}

		return data[idx];
	}

	size_t size() const
	{
		return nr_elems;
	}

	T& front()
	{
		return this->operator[](0);
	}

	T& back()
	{
		return this->operator[](nr_elems - 1);
	}

	size_t buf_size() const
	{
		return buffer_size;
	}

	void set_nr_elems(size_t nr)
	{
		nr_elems = nr;
	}

	T* begin()
	{
		return data;
	}

	T* end()
	{
		return &data[nr_elems];
	}

	const T* cbegin() const
	{
		return data;
	}

	const T* cend() const
	{
		return &data[nr_elems];
	}

	T *get_buf()
	{
		return data;
	}

	const T *get_buf() const
	{
		return data;
	}
};

};

#endif