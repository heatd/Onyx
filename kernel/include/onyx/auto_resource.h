/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_AUTO_RESOURCE_H
#define _ONYX_AUTO_RESOURCE_H


/**
 * @brief auto_resource - automatically manages resources that implement T::ref() and T::unref().
 * 
 * @tparam ResourceType The type of the resource
 */
template <typename ResourceType>
class auto_resource
{
private:
	/* Hmmm, reference or pointer? I'm preferring pointer here because it's more flexible;
	 * you can use operator= to re-assign stuff.
	 */
	ResourceType *res;
public:
	constexpr auto_resource() : res{nullptr} {}
	constexpr auto_resource(ResourceType *r) : res{r} {}

	auto_resource(const auto_resource& ar) : res{ar.res}
	{
		if(valid_resource())
			ref();
	}

	auto_resource& operator=(const auto_resource& ar)
	{
		if(valid_resource())
			unref();

		res = ar.res;

		if(valid_resource())
			ref();
		
		return *this;
	}

	void ref() const
	{
		res->ref();
	}

	void unref() const
	{
		res->unref();
	}

	bool valid_resource() const
	{
		return res != nullptr;
	}

	auto_resource(auto_resource&& ar) : res{ar.res}
	{
		ar.res = nullptr;
	}

	auto_resource& operator=(auto_resource&& ar)
	{
		res = ar.res;
		ar.res = nullptr;

		return *this;
	}

	~auto_resource()
	{
		if(valid_resource())
			unref();
	}

	ResourceType *release()
	{
		auto ret = res;
		res = nullptr;

		return ret;
	}

	ResourceType *get() const
	{
		return res;
	}

	operator bool() const
	{
		return valid_resource();
	}

	bool operator!() const
	{
		return !valid_resource();
	}

	ResourceType *operator->() const
	{
		return get();
	}

	operator ResourceType*() const
	{
		return get();
	}

	bool operator==(const auto_resource<ResourceType>& rhs) const
	{
		return get() == rhs.get();
	}
};

#endif
