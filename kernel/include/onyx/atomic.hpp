/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_ATOMIC_H
#define _CARBON_ATOMIC_H

#include <onyx/enable_if.h>
#include <onyx/is_integral.h>
#include <onyx/conditional.h>

#ifdef __GNUG__
enum class mem_order : int
{
	acq_rel = __ATOMIC_ACQ_REL,
	acquire = __ATOMIC_ACQUIRE,
	consume = __ATOMIC_CONSUME,
#ifndef __clang__
	hle_acquire = __ATOMIC_HLE_ACQUIRE,
	hle_release = __ATOMIC_HLE_RELEASE,
#endif
	relaxed = __ATOMIC_RELAXED,
	release = __ATOMIC_RELEASE,
	seq_cst = __ATOMIC_SEQ_CST
};

#else

#error This compiler is not supported

#endif

template <typename type>
class atomic_primitive
{
protected:
	type val;
public:
	constexpr atomic_primitive(type v) : val{v} {}
	constexpr atomic_primitive() : val{} {}

	type load(mem_order order = mem_order::seq_cst) const
	{
		return __atomic_load_n(&val, (int) order);
	}

	void store(type t, mem_order order = mem_order::seq_cst)
	{
		__atomic_store_n(&val, t, (int) order);
	}

	type add_fetch(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_add_fetch(&val, v, (int) order);
	}

	type fetch_add(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_fetch_add(&val, v, (int) order);
	}

	type sub_fetch(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_sub_fetch(&val, v, (int) order);
	}

	type fetch_sub(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_fetch_sub(&val, v, (int) order);
	}

	type and_fetch(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_and_fetch(&val, v, (int) order);
	}

	type fetch_and(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_fetch_and(&val, v, (int) order);
	}

	type or_fetch(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_or_fetch(&val, v, (int) order);
	}

	type fetch_or(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_fetch_or(&val, v, (int) order);
	}

	type xor_fetch(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_xor_fetch(&val, v, (int) order);
	}

	type fetch_xor(type v, mem_order order = mem_order::seq_cst)
	{
		return __atomic_fetch_xor(&val, v, (int) order);
	}

	bool compare_exchange_weak(type& expected, type desired, mem_order success, mem_order failure)
	{
		return __atomic_compare_exchange_n(&val, &expected, desired,
		                               true, (int) success, (int) failure);
	}

	bool compare_exchange_weak(type& expected, type desired, mem_order order = mem_order::seq_cst)
	{
		return __atomic_compare_exchange_n(&val, &expected, desired,
		                               true, (int) order, (int) order);
	}

	bool compare_exchange_strong(type& expected, type desired, mem_order success, mem_order failure)
	{
		return __atomic_compare_exchange_n(&val, &expected, desired,
		                               false, (int) success, (int) failure);
	}

	bool compare_exchange_strong(type& expected, type desired, mem_order order = mem_order::seq_cst)
	{
		return __atomic_compare_exchange_n(&val, &expected, desired,
		                               false, (int) order, (int) order);
	}
};

template <typename type>
class atomic_complex_type
{
protected:
	type val;
public:
	virtual type load(mem_order order = mem_order::seq_cst) = 0;

	virtual void store(type t, mem_order order = mem_order::seq_cst) = 0;

	virtual type add_fetch(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type fetch_add(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type sub_fetch(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type fetch_sub(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type and_fetch(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type fetch_and(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type or_fetch(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type fetch_or(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type xor_fetch(type v, mem_order order = mem_order::seq_cst) = 0;
	virtual type fetch_xor(type v, mem_order order = mem_order::seq_cst) = 0;
};

template <typename type> 
class atomic : public conditional<is_integral_v<type>, atomic_primitive<type>,
		      atomic_complex_type<type> >::type
{
private:
public:
	constexpr atomic(type v) : conditional<is_integral_v<type>, atomic_primitive<type>,
		      atomic_complex_type<type> >::type(v) {}
	constexpr atomic() : conditional<is_integral_v<type>, atomic_primitive<type>,
		      atomic_complex_type<type> >::type() {}

	/* pre increment */
	type operator++()
	{
		return this->add_fetch(1);
	}
	/* post increment */
	type operator++(int)
	{
		return this->fetch_add(1);
	}

	/* pre decrement */
	type operator--()
	{
		return this->sub_fetch(1);
	}

	type operator--(int)
	{
		return this->fetch_sub(1);
	}

	type operator=(type new_val)
	{
		this->store(new_val);
		return new_val;
	}

	type operator+=(type inc)
	{
		return this->add_fetch(inc);
	}

	type operator-=(type inc)
	{
		return this->sub_fetch(inc);
	}

	operator type() const
	{
		return this->load();
	}
};

namespace cul
{

using atomic_uint = ::atomic<unsigned int>;

}

static inline void atomic_thread_fence(mem_order order)
{
	__atomic_thread_fence((int) order);
}


#endif
