/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

// The virt machine's UART is a PL011

#include <stddef.h>
#include <stdint.h>

#include <onyx/serial.h>
#include <onyx/vm.h>

volatile uint32_t *uart_base = (volatile uint32_t *) PHYS_TO_VIRT(0x09000000);

static inline uint32_t uart_read_32(size_t offset)
{
    return *(volatile uint32_t *) ((char *) uart_base + offset);
}

static inline void uart_write_32(size_t offset, uint32_t val)
{
    *(volatile uint32_t *) ((char *) uart_base + offset) = val;
}

void platform_serial_init(void)
{
}

void serial_putc(char c)
{
    while ((uart_read_32(0x18) & (1 << 5)))
        ;
    uart_write_32(0, c);
}

void platform_serial_write(const char *s, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        // We need to do this since we have no tty layer before us to deal with this translation
        if (s[i] == '\n')
            serial_putc('\r');
        serial_putc(s[i]);
    }
}
