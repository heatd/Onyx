/*
 * Copyright (c) 2019 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_BITMAP_H
#define _ONYX_BITMAP_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/conditional.h>
#include <onyx/limits.h>

class DynamicBitmap
{
protected:
    unsigned long *bitmap;
    size_t size;

public:
    constexpr DynamicBitmap(size_t size) : bitmap{}, size{size}
    {
    }

    ~DynamicBitmap()
    {
        if (bitmap)
            free(bitmap);
    }

    constexpr size_t get_size() const
    {
        return size;
    }

    void set_size(size_t _size)
    {
        size = _size;
    }

    size_t size_in_longs() const
    {
        return size / (8 * sizeof(unsigned long));
    }

    inline bool allocate_bitmap(unsigned char filler = 0x0)
    {
        size_t nr_bytes = size / 8;
        if (size % 8)
            nr_bytes++;

        bitmap = (unsigned long *) malloc(size_in_longs() * sizeof(unsigned long));
        if (!bitmap)
            return false;
        memset(bitmap, filler, nr_bytes);

        return true;
    }

    inline bool realloc_bitmap(size_t new_size, unsigned char filler = 0x0)
    {
        size_t old_nr_bytes = size / 8;
        if (size % 8)
            old_nr_bytes++;

        size_t nr_bytes = new_size / 8;
        if (new_size % 8)
            nr_bytes++;

        auto new_size_in_longs = nr_bytes / sizeof(unsigned long);
        if (nr_bytes % sizeof(unsigned long))
            new_size_in_longs++;

        auto _bitmap = realloc(bitmap, new_size_in_longs * sizeof(unsigned long));
        if (!_bitmap)
            return false;
        memset((char *) _bitmap + old_nr_bytes, filler, nr_bytes - old_nr_bytes);

        bitmap = (unsigned long *) _bitmap;
        size = new_size;

        return true;
    }

    DynamicBitmap &operator=(DynamicBitmap &&rhs)
    {
        if (this == &rhs)
            return *this;

        bitmap = rhs.bitmap;
        rhs.bitmap = nullptr;
        size = rhs.size;
        return *this;
    }

    DynamicBitmap(DynamicBitmap &&rhs)
    {
        if (this == &rhs)
            return;

        bitmap = rhs.bitmap;
        rhs.bitmap = nullptr;
        size = rhs.size;
    }
};

template <size_t size>
class StaticBitmap
{
protected:
    unsigned long bitmap[size];
    constexpr StaticBitmap(size_t len)
    {
        for (auto &b : bitmap)
            b = 0;
    }

public:
    constexpr size_t get_size() const
    {
        return size;
    }

    constexpr void set_size(size_t len)
    {
        (void) len;
    }

    constexpr size_t size_in_longs() const
    {
        return size / (8 * sizeof(unsigned long));
    }
};

template <size_t s, bool static_bitmap = false>
class Bitmap : public conditional<static_bitmap, StaticBitmap<s>, DynamicBitmap>::type
{
private:
    using BaseType = typename conditional<static_bitmap, StaticBitmap<s>, DynamicBitmap>::type;
    static constexpr unsigned long bits_per_entry = sizeof(unsigned long) * 8;

public:
    constexpr Bitmap() : BaseType(s)
    {
    }

    constexpr bool find_free_bit(unsigned long *bit)
    {
        for (size_t i = 0; i < this->size_in_longs(); i++)
        {
            if (this->bitmap[i] == ULONG_MAX)
                continue;

            for (size_t j = 0; j < bits_per_entry; j++)
            {
                if (i * bits_per_entry + j > this->get_size())
                    return false;
                if (!(this->bitmap[i] & (1UL << j)))
                {
                    this->bitmap[i] |= (1UL << j);
                    *bit = i * bits_per_entry + j;
                    return true;
                }
            }
        }

        return false;
    }

    constexpr bool is_set(unsigned long bit) const
    {
        unsigned long byte_idx = bit / bits_per_entry;
        unsigned long bit_idx = bit % bits_per_entry;

        return this->bitmap[byte_idx] & (1UL << bit_idx);
    }

    constexpr void set_bit(unsigned long bit)
    {
        unsigned long byte_idx = bit / bits_per_entry;
        unsigned long bit_idx = bit % bits_per_entry;

        this->bitmap[byte_idx] |= (1UL << bit_idx);
    }

    constexpr void free_bit(unsigned long bit)
    {
        unsigned long byte_idx = bit / bits_per_entry;
        unsigned long bit_idx = bit % bits_per_entry;

        this->bitmap[byte_idx] &= ~(1UL << bit_idx);
    }
};

#endif
