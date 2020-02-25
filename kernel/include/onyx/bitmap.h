/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _CARBON_BITMAP_H
#define _CARBON_BITMAP_H

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include <onyx/spinlock.h>
#include <onyx/scoped_lock.h>
#include <onyx/conditional.h>

class DynamicBitmap
{
protected:
	unsigned long *bitmap;
};

template <size_t size>
class StaticBitmap
{
protected:
	unsigned long bitmap[size];
};

template <size_t s, bool static_bitmap = false>
class Bitmap : public conditional<static_bitmap, StaticBitmap<s>, DynamicBitmap>::type
{
private:
	unsigned long *bitmap;
	size_t size;
	size_t size_in_longs;
	static constexpr unsigned long bits_per_entry = sizeof(unsigned long) * 8;
public:
	Bitmap() : bitmap{}, size(s)
	{
		size_in_longs = size / (8 * sizeof(unsigned long));
		if(size % (8 * sizeof(unsigned long)))
			size_in_longs++;
	}

	inline size_t GetSize()
	{
		return size;
	}

	inline void SetSize(size_t _size)
	{
		size = _size;
	}

	inline bool AllocateBitmap(unsigned char filler = 0x0)
	{
		assert(static_bitmap != true);
		size_t nr_bytes = size / 8;
		if(size % 8)
			nr_bytes++;

		size_in_longs = nr_bytes / sizeof(unsigned long);
		if(nr_bytes % sizeof(unsigned long))
			size_in_longs++;

		bitmap = (unsigned long *) malloc(nr_bytes);
		if(!bitmap)
			return false;
		memset(bitmap, filler, nr_bytes);

		return true;
	}

	inline bool ReallocBitmap(size_t new_size, unsigned char filler = 0x0)
	{
		size_t old_nr_bytes = size / 8;
		if(size % 8)
			old_nr_bytes++;

		size_t nr_bytes = new_size / 8;
		if(new_size % 8)
			nr_bytes++;

		auto new_size_in_longs = nr_bytes / sizeof(unsigned long);
		if(nr_bytes % sizeof(unsigned long))
			new_size_in_longs++;

		auto _bitmap = realloc(bitmap, nr_bytes);
		if(!_bitmap)
			return false;
		memset((char *) _bitmap + old_nr_bytes, filler, nr_bytes - old_nr_bytes);

		bitmap = (unsigned long *) _bitmap;
		size = new_size;
		size_in_longs = new_size_in_longs;
	
		return true;
	}

	inline bool FindFreeBit(unsigned long *bit)
	{
		for(size_t i = 0; i < size_in_longs; i++)
		{
			if(bitmap[i] == ULONG_MAX)
				continue;
			
			for(size_t j = 0; j < bits_per_entry; j++)
			{
				if(i * bits_per_entry + j > size)
					return false;
				if(!(bitmap[i] & (1UL << j)))
				{
					bitmap[i] |= (1UL << j);
					*bit = i * bits_per_entry + j;
					return true;
				}
			}
		}

		return false;
	}

	inline bool IsSet(unsigned long bit)
	{
		unsigned long byte_idx = bit / bits_per_entry;
		unsigned long bit_idx = bit % bits_per_entry;

		return bitmap[byte_idx] & (1UL << bit_idx);
	}

	inline void SetBit(unsigned long bit)
	{
		unsigned long byte_idx = bit / bits_per_entry;
		unsigned long bit_idx = bit % bits_per_entry;

		bitmap[byte_idx] |= (1UL << bit_idx);
	}

	inline void FreeBit(unsigned long bit)
	{
		unsigned long byte_idx = bit / bits_per_entry;
		unsigned long bit_idx = bit % bits_per_entry;

		bitmap[byte_idx] &= ~(1UL << bit_idx);
	}
};

#endif