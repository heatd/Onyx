/*
 * Copyright (c) 2019-2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_HWREGISTER_HPP
#define _ONYX_HWREGISTER_HPP

#include <stdint.h>

class mmio_range
{
private:
    volatile uint8_t *base;

public:
    using register_offset = unsigned long;

    constexpr mmio_range(volatile void *__b) : base(static_cast<volatile uint8_t *>(__b))
    {
    }
    constexpr mmio_range() : base{nullptr}
    {
    }
    ~mmio_range()
    {
    }

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

    // Helpers for read and write functions of common types
#define HWREGISTER_INTERNAL_READx(width, read_backend)                 \
    uint##width##_t read##width(mmio_range::register_offset off) const \
    {                                                                  \
        return read_backend<uint##width##_t>(off);                     \
    }

#define HWREGISTER_INTERNAL_WRITEx(width, write_backend)                    \
    void write##width(mmio_range::register_offset off, uint##width##_t val) \
    {                                                                       \
        write_backend<uint##width##_t>(off, val);                           \
    }

    HWREGISTER_INTERNAL_READx(8, read);
    HWREGISTER_INTERNAL_READx(16, read);
    HWREGISTER_INTERNAL_READx(32, read);
    HWREGISTER_INTERNAL_READx(64, read);

    HWREGISTER_INTERNAL_WRITEx(8, write);
    HWREGISTER_INTERNAL_WRITEx(16, write);
    HWREGISTER_INTERNAL_WRITEx(32, write);
    HWREGISTER_INTERNAL_WRITEx(64, write);

    volatile uint8_t *as_ptr() const
    {
        return base;
    }

    void set_base(volatile void *__b)
    {
        base = static_cast<volatile uint8_t *>(__b);
    }
};

#define DEFINE_MMIO_RW_FUNCTIONS(mmio_range_name)                           \
    template <typename Type>                                                \
    Type mmio_range_name##_read(mmio_range::register_offset off) const      \
    {                                                                       \
        return mmio_range_name.read<Type>(off);                             \
    }                                                                       \
                                                                            \
    template <typename Type>                                                \
    void mmio_range_name##_write(mmio_range::register_offset off, Type val) \
    {                                                                       \
        mmio_range_name.write<Type>(off, val);                              \
    }                                                                       \
                                                                            \
    HWREGISTER_INTERNAL_READx(8, mmio_range_name##_read);                   \
    HWREGISTER_INTERNAL_READx(16, mmio_range_name##_read);                  \
    HWREGISTER_INTERNAL_READx(32, mmio_range_name##_read);                  \
    HWREGISTER_INTERNAL_READx(64, mmio_range_name##_read);                  \
                                                                            \
    HWREGISTER_INTERNAL_WRITEx(8, mmio_range_name##_write);                 \
    HWREGISTER_INTERNAL_WRITEx(16, mmio_range_name##_write);                \
    HWREGISTER_INTERNAL_WRITEx(32, mmio_range_name##_write);                \
    HWREGISTER_INTERNAL_WRITEx(64, mmio_range_name##_write);

#endif
