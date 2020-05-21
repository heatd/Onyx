/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _SMART_KERNEL_H
#define _SMART_KERNEL_H

#include <assert.h>

#include <onyx/remove_extent.h>

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
		if(data)
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
		/* 1 - 1 = 0! */
		if(__sync_fetch_and_sub(&ref, 1) == 1)
		{
			delete data;
			data = nullptr;
			/* Commit sudoku */
			delete this;
		}
	}
	
	void refer(void)
	{
		__sync_fetch_and_add(&ref, 1);
	}
};

template <typename T>
class shared_ptr
{
private:
	refcount<T> *ref;
	using element_type = remove_extent_t<T>;
public:
	shared_ptr() : ref(nullptr) {}
	shared_ptr(T *data)
	{
		if(data != nullptr)
			ref = new refcount<T>(data);
		else
			ref = nullptr;
	}

	refcount<T> *__get_refc() const
	{
		return ref;
	}

	void __set_refc(refcount<T> *r)
	{
		if(ref)
			ref->release();
		r->refer();
		ref = r;
	}

	template <typename Type>
	shared_ptr(const shared_ptr<Type>& ptr)
	{
		auto refc = ptr.__get_refc();
		if(refc)
			refc->refer();
		ref = refc;
	}

	void __reset()
	{
		ref = nullptr;
	}

	template <typename Type>
	shared_ptr(shared_ptr<Type>&& ptr) : ref(ptr.ref)
	{
		ptr.__reset();
	}

	template <typename Type>
	shared_ptr& operator=(shared_ptr<Type>&& ptr)
	{
		if(ref)
		{
			ref->release();
			ref = nullptr;
		}

		ref = ptr.__get_refc();
		ptr.__reset();

		return *this;
	}

	template <typename Type>
	shared_ptr& operator=(const shared_ptr<Type>& p)
	{
		auto refc = p.__get_refc();

		if(ref == refc)
			goto ret;
		if(ref)
		{
			ref->release();
			ref = nullptr;
		}

		if(refc)
		{
			refc->refer();
			ref = refc;
		}
	ret:
		return *this;
	}

	bool operator==(const shared_ptr& p)
	{
		return (p.ref == ref);
	}

	bool operator==(const T *ptr)
	{
		if(!ref && !ptr)
			return true;
		else if(!ref)
			return false;
		
		return (ref->get_data() == ptr);
	}

	bool operator!=(const shared_ptr& p)
	{
		return !operator==(p);
	}

	bool operator!=(const T *ptr)
	{
		return !operator==(ptr);
	}

	element_type& operator[](size_t index)
	{
		return ref->data[index];
	}

	~shared_ptr(void)
	{
		/* Order this in order to be thread-safe */
		auto r = ref;
		ref = nullptr;

		if(r) r->release();
	}

	T* get_data()
	{
		if(!ref)
			return nullptr;
		return ref->get_data();
	}

	T& operator*()
	{
		return *get_data();
	}
	
	T* operator->()
	{
		return get_data();
	}

	bool operator!()
	{
		return get_data() == nullptr;
	}
	
	operator bool()
	{
		return get_data() != nullptr;
	}
};

template <typename T>
class unique_ptr
{
private:
	T *p;
	using element_type = remove_extent_t<T>;
public:
	unique_ptr() : p(nullptr) {}
	unique_ptr(T *data) : p(data)
	{
	}

	unique_ptr(const unique_ptr& ptr) = delete;

	T *release()
	{
		auto ret = p;
		p = nullptr;
		return ret;
	}

	void reset(T *new_ptr)
	{
		delete p;
		p = new_ptr;
	}

	template <typename Type>
	unique_ptr(unique_ptr<Type>&& ptr) : p(ptr.p)
	{
		ptr.p = nullptr;
	}

	template <typename Type>
	unique_ptr& operator=(unique_ptr<Type>&& ptr)
	{
		reset(ptr.release());
		return *this;
	}

	unique_ptr& operator=(const unique_ptr& p) = delete;

	bool operator==(const unique_ptr& p) const
	{
		return (p == p.p);
	}

	bool operator==(const T *ptr) const
	{	
		return (p == ptr);
	}

	bool operator!=(const unique_ptr& p) const
	{
		return !operator==(p);
	}

	bool operator!=(const T *ptr) const
	{
		return !operator==(ptr);
	}

	element_type& operator[](size_t index)
	{
		return p[index];
	}

	~unique_ptr(void)
	{
		if(p)
			delete p;
	}

	T* get_data() const
	{
		return p;
	}

	T& operator*() const
	{
		return *get_data();
	}
	
	T* operator->() const
	{
		return get_data();
	}

	bool operator!()
	{
		return get_data() == nullptr;
	}
	
	operator bool()
	{
		return get_data() != nullptr;
	}
};

template <typename T, class ... Args>
shared_ptr<T> make_shared(Args && ... args)
{
	char *buf = (char *) malloc(sizeof(refcount<T>) + sizeof(T));
	if(!buf)
		return nullptr;

	refcount<T> *refc = new (buf) refcount<T>();
	T *data = new (buf + sizeof(refcount<T>)) T(args...);

	shared_ptr<T> p(nullptr);
	p.__set_refc(refc);
	return p;
}

template <typename T, typename U>
shared_ptr<T> cast(const shared_ptr<U>& s)
{
	auto ref = s.__get_refc();
	shared_ptr<T> p{};
	p.__set_refc((refcount<T> *) ref);
	return p;
}

template <typename T, class ... Args>
unique_ptr<T> make_unique(Args && ... args)
{
	T *data = new T(args...);
	if(!data)
		return nullptr;

	unique_ptr<T> p(data);
	return p;
}

#endif
