/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NO_PORT_IO_H
#define _ONYX_NO_PORT_IO_H

#include <stdint.h>

namespace noport_io
{
namespace internal
{
[[noreturn]] inline void die()
{
    __builtin_trap();
}
} // namespace internal
} // namespace noport_io

static inline void outb(uint16_t port, uint8_t val)
{
    noport_io::internal::die();
}

static inline void outw(uint16_t port, uint16_t val)
{
    noport_io::internal::die();
}

static inline void outl(uint16_t port, uint32_t val)
{
    noport_io::internal::die();
}

static inline uint8_t inb(uint16_t port)
{
    noport_io::internal::die();
}

static inline uint16_t inw(uint16_t port)
{
    noport_io::internal::die();
}

static inline uint32_t inl(uint16_t port)
{
    noport_io::internal::die();
}

static inline void io_wait(void)
{
    noport_io::internal::die();
}

#endif
