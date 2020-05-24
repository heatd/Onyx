/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _SMART_KERNEL_H
#define _SMART_KERNEL_H

#include <assert.h>

#include <onyx/remove_extent.h>

static constexpr unsigned char _R__refc_was_make_shared = (1 << 0);

template <typename T>
class refcount
{
private:
	unsigned long ref;
	T *data;
	unsigned char flags;
public:
	refcount() : ref(1), data(nullptr){}
	refcount(T *d) : ref(1), data(d){}
	refcount(unsigned char flags) : ref(0), data{nullptr}, flags{flags}{}
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
			if(!(flags & _R__refc_was_make_shared)) [[unlikely]]
				delete data;
			else
				data->~T();

			data = nullptr;
			/* Commit sudoku */
			delete this;
		}
	}
	
	void refer(void)
	{
		__sync_fetch_and_add(&ref, 1);
	}

	void __set_data(T *d)
	{
		data = d;
	}

	void __set_refs(unsigned long refs)
	{
		ref = refs;
	}
};

template <typename T>
class shared_ptr
{
private:
	refcount<T> *ref;
	T *p;
	using element_type = remove_extent_t<T>;
public:
	shared_ptr() : ref(nullptr), p{nullptr} {}
	shared_ptr(T *data)
	{
		if(data != nullptr)
			ref = new refcount<T>(data);
		else
			ref = nullptr;
		p = data;
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
		p = r->get_data();
	}

	template <typename Type>
	shared_ptr(const shared_ptr<Type>& ptr)
	{
		auto refc = ptr.__get_refc();
		if(refc)
			refc->refer();
		ref = refc;
		p = refc->get_data();
	}

	void __reset()
	{
		ref = nullptr;
		p = nullptr;
	}

	template <typename Type>
	shared_ptr(shared_ptr<Type>&& ptr) : ref(ptr.ref), p(ptr.get_data())
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
			p = nullptr;
		}

		ref = ptr.__get_refc();
		p = ptr.get_data();
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
			p = nullptr;
		}

		if(refc)
		{
			refc->refer();
			ref = refc;
			p = refc->get_data();
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
		auto r = ref;
		ref = nullptr;
		p = nullptr;

		if(r) r->release();
	}

	T* get_data()
	{
		return p;
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

	typedef decltype(nullptr) nullptr_t;

	unique_ptr(nullptr_t data) : p(nullptr)
	{

	}

	explicit unique_ptr(T *data) : p(data)
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
	unique_ptr(unique_ptr<Type>&& ptr) : p(ptr.release())
	{

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

	refcount<T> *refc = new (buf) refcount<T>(_R__refc_was_make_shared);
	T *data = new (buf + sizeof(refcount<T>)) T(args...);
	refc->__set_data(data);

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
