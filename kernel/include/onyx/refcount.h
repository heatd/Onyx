/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_REFCOUNT_H
#define _CARBON_REFCOUNT_H

#include <assert.h>

#include <onyx/deleter.hpp>
#include <onyx/atomic.hpp>

class refcountable
{
public:
	atomic <unsigned long> __refcount;

	/* Note: refcountable() defaults to a refcount of 1 */
	constexpr refcountable() : __refcount(1) {}
	constexpr refcountable(unsigned long init) : __refcount(init) {}

	virtual ~refcountable() {}

	unsigned long ref()
	{
		return ++__refcount;
	}

	unsigned long refer_multiple(unsigned long n)
	{
		return __refcount.add_fetch(n);
	}

	bool unref()
	{
		bool was_deleted = false;
		if(--__refcount == 0)
		{
			was_deleted = true;
			delete this;
		}

		return was_deleted;
	}

	bool unref_multiple(unsigned long n)
	{
		bool was_deleted = false;
		if(__refcount.sub_fetch(n) == 0)
		{
			was_deleted = true;
			delete this;
		}

		return was_deleted;
	}
};

template <typename T>
class ref_guard
{
private:
	T *p;
	atomic<unsigned long> refed_counter;
public:
	void ref()
	{
		p->ref();
		refed_counter++;
	}

	void unref()
	{
		p->unref();
		refed_counter--;
	}

	void unref_everything()
	{
		p->unref_multiple();
	}

	void disable()
	{
		refed_counter = 0;
		p = nullptr;
	}

	ref_guard(T *p) : p(p)
	{
		ref();
	}

	ref_guard(const ref_guard& r) : p(r.ptr), refed_counter(r.refed_counter)
	{
		p->refer_multiple(refed_counter);
	}

	ref_guard(ref_guard&& r) : p(r.ptr), refed_counter(r.refed_counter)
	{
		p->refer_multiple(refed_counter);
		r.ptr = nullptr;
		r.refed_counter = 0;
	}

	ref_guard& operator=(const ref_guard& r)
	{
		/* If we have something we're pointing to,
		 * this idiom is dangerous and I don't like it, so just ban it outright.
		*/
		assert(p == nullptr);

		p = r.ptr;
		refed_counter = r.refed_counter;
		p->refer_multiple(refed_counter);

		return *this;
	}

	ref_guard& operator=(ref_guard&& r)
	{
		p = r.ptr;
		refed_counter = r.refed_counter;
		r.ptr = nullptr;
		r.refed_counter = 0;

		return *this;
	}

	~ref_guard()
	{
		unref_everything();
	}
};

#endif