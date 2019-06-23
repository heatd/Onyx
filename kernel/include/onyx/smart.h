/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _SMART_KERNEL_H
#define _SMART_KERNEL_H

#include <assert.h>

template <typename T>
class refcount
{
private:
	long ref;
	T *data;
public:
	refcount() : ref(1), data(nullptr){}
	refcount(T *d): ref(1), data(d){}
	~refcount()
	{
		delete data;
	}
	long get_ref(void)
	{
		return ref;
	}
	T *get_data(void)
	{
		return data;
	}
	void release(void)
	{
		if(__sync_fetch_and_sub(&ref, 1) == 0)
		{
			delete data;
		}
	}
	void refer(void)
	{
		__sync_fetch_and_add(&ref, 1);
	}
};

template <typename T>
class smart_ptr
{
private:
	refcount<T> *ref;
public:
	smart_ptr() : ref(nullptr){}
	smart_ptr(T *data)
	{
		ref = new refcount<T>(data);
	}
	
	smart_ptr(smart_ptr& ptr)
	{
		ref = ptr.ref;
	}
	
	~smart_ptr(void)
	{
		if(ref) ref->release();
	}
	
	smart_ptr& operator=(const smart_ptr &p)
	{
		if(ref == p.ref)
			goto ret;
		if(ref)
		{
			ref->release();
			ref = nullptr;
		}
		p.ref->refer();
		ref = p.ref;
	ret:
		return *this;
	}
	
	T& operator*()
	{
		return *ref->get_data();
	}
	
	T* operator->()
	{
		return ref->get_data();
	}
	
	T* get_data()
	{
		return ref->get_data();
	}
};

namespace smartptr
{

template<class T, class ... Args>
smart_ptr<T> make(Args && ... args)
{
	T *data = new T(args...);
	smart_ptr<T> p(data);
	return p;
}

};
#endif
