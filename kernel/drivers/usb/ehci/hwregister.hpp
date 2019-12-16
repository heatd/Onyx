/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#pragma once

#include <stdint.h>

class mmio_range
{
private:
	volatile uint8_t *base;
public:
	using register_offset = unsigned long;
 
	constexpr mmio_range(volatile void *__b) : base(static_cast<volatile uint8_t *>(__b)) {}
	constexpr mmio_range() : base{nullptr} {}
	~mmio_range() {}

	template <typename Type>
	Type read(register_offset off) const
	{
		return *reinterpret_cast<volatile Type *>(base + off);
	}

	template <typename Type>
	void write(register_offset off, Type val)
	{
		volatile Type *t = reinterpret_cast<volatile Type *>(base + off);
		*t = val;
	}

	volatile uint8_t *as_ptr() const
	{
		return base;
	}

	void set_base(volatile void *__b)
	{
		base = static_cast<volatile uint8_t *>(__b);
	}
};