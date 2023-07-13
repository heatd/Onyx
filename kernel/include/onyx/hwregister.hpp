/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_HWREGISTER_HPP
#define _ONYX_HWREGISTER_HPP

#include <assert.h>
#include <stdint.h>

#include <onyx/dev_resource.h>
#include <onyx/new.h>
#include <onyx/port_io.h>
#include <onyx/vm.h>

#include <onyx/utility.hpp>

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

    ~mmio_range() = default;

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

class io_range
{
private:
    uint16_t base;

public:
    using register_offset = unsigned long;

    constexpr io_range(uint16_t __b) : base(__b)
    {
    }

    constexpr io_range() : base{0}
    {
    }

    ~io_range() = default;

    template <typename Type>
    Type read(register_offset off) const
    {
        assert(sizeof(Type) <= 4);
        switch (sizeof(Type))
        {
            case 1:
                return inb(base + off);
            case 2:
                return inw(base + off);
            case 4:
                return inl(base + off);
            default:
                __builtin_trap();
        }
    }

    template <typename Type>
    void write(register_offset off, Type val)
    {
        assert(sizeof(Type) <= 4);
        switch (sizeof(Type))
        {
            case 1:
                outb(base + off, val);
                break;
            case 2:
                outw(base + off, val);
                break;
            case 4:
                outl(base + off, val);
                break;
            default:
                __builtin_trap();
        }
    }

// Helpers for read and write functions of common types
#define IOREGISTER_INTERNAL_READx(width, read_backend)     \
    uint##width##_t read##width(register_offset off) const \
    {                                                      \
        return read_backend<uint##width##_t>(off);         \
    }

#define IOREGISTER_INTERNAL_WRITEx(width, write_backend)        \
    void write##width(register_offset off, uint##width##_t val) \
    {                                                           \
        write_backend<uint##width##_t>(off, val);               \
    }

    IOREGISTER_INTERNAL_READx(8, read);
    IOREGISTER_INTERNAL_READx(16, read);
    IOREGISTER_INTERNAL_READx(32, read);

    IOREGISTER_INTERNAL_WRITEx(8, write);
    IOREGISTER_INTERNAL_WRITEx(16, write);
    IOREGISTER_INTERNAL_WRITEx(32, write);

    uint16_t as_ioport() const
    {
        return base;
    }

    void set_base(uint16_t __b)
    {
        base = __b;
    }
};

class hw_range
{
private:
    union {
        mmio_range mmio;
        io_range io;
    };
    bool is_io;

public:
    hw_range(dev_resource *res)
    {
        if (res->flags() & DEV_RESOURCE_FLAG_MEM)
        {
            is_io = false;
            new (&mmio) mmio_range((volatile void *) res->start());
        }
        else
        {
            is_io = true;
            new (&io) io_range((uint16_t) res->start());
        }
    }

    bool init(dev_resource *res)
    {
        if (!is_io)
        {
            void *ptr =
                mmiomap((void *) res->start(), res->size(), VM_WRITE | VM_READ | VM_NOCACHE);
            if (!ptr)
                return false;
            mmio.set_base(ptr);
        }

        return true;
    }

    hw_range(uint16_t port) : io{port}, is_io{true}
    {
    }

    hw_range(volatile void *ptr) : mmio{ptr}, is_io{false}
    {
    }

    template <typename Callable>
    hw_range(dev_resource *res, Callable mapping_callback)
    {
        if (res->flags() & DEV_RESOURCE_FLAG_MEM)
        {
            is_io = false;
            new (&mmio) mmio_range(mapping_callback(res));
        }
        else
        {
            is_io = true;
            new (&io) io_range((uint16_t) res->start());
        }
    }

    hw_range &operator=(hw_range &&r)
    {
        if (&r == this)
            return *this;
        if (r.is_io)
            io = r.io;
        else
            mmio = r.mmio;
        is_io = r.is_io;
        return *this;
    }

    hw_range(hw_range &&r)
    {
        operator=(cul::move(r));
    }

    hw_range &operator=(const hw_range &r)
    {
        if (&r == this)
            return *this;
        if (r.is_io)
            io = r.io;
        else
            mmio = r.mmio;
        is_io = r.is_io;
        return *this;
    }

    ~hw_range()
    {
        is_io ? io.~io_range() : mmio.~mmio_range();
    }

    hw_range(const hw_range &r)
    {
        operator=(r);
    }

    using register_offset = size_t;

    template <typename Type>
    Type read(register_offset off) const
    {
        return is_io ? io.read<Type>(off) : mmio.read<Type>(off);
    }

    template <typename Type>
    void write(register_offset off, Type val)
    {
        is_io ? io.write(off, val) : mmio.write(off, val);
    }

    IOREGISTER_INTERNAL_READx(8, read);
    IOREGISTER_INTERNAL_READx(16, read);
    IOREGISTER_INTERNAL_READx(32, read);
    IOREGISTER_INTERNAL_READx(64, read);

    IOREGISTER_INTERNAL_WRITEx(8, write);
    IOREGISTER_INTERNAL_WRITEx(16, write);
    IOREGISTER_INTERNAL_WRITEx(32, write);
    IOREGISTER_INTERNAL_WRITEx(64, write);

    unsigned long base() const
    {
        return is_io ? io.as_ioport() : (unsigned long) mmio.as_ptr();
    }
};

#endif
